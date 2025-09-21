import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get("Upgrade");

    // Only handle WebSocket connections on /vpn path
    if (upgradeHeader === "websocket" && url.pathname === "/vpn") {
      // Extract UUID from header or query parameter
      let userUUID = null;
      
      // Option 1: From WebSocket subprotocol
      const protocolHeader = request.headers.get("Sec-WebSocket-Protocol");
      if (protocolHeader) {
        const protocols = protocolHeader.split(",").map(p => p.trim());
        const uuidProtocol = protocols.find(p => p.startsWith("uuid="));
        if (uuidProtocol) {
          userUUID = uuidProtocol.substring(5);
        }
      }
      
      // Option 2: From query parameter
      if (!userUUID) {
        userUUID = url.searchParams.get("uuid");
      }
      
      // Validate UUID
      if (!userUUID || !validateUUID(userUUID)) {
        return new Response("Invalid or missing UUID", { status: 400 });
      }
      
      // Get user's proxy selection from KV
      let selectedProxy = null;
      if (env.USER_PROXY_KV) {
        selectedProxy = await env.USER_PROXY_KV.get(userUUID);
      }
      
      if (!selectedProxy) {
        return new Response("No proxy found for this UUID", { status: 404 });
      }
      
      // Handle WebSocket connection
      const webSocketPair = new WebSocketPair();
      const [client, webSocket] = Object.values(webSocketPair);
      webSocket.accept();
      
      // Send UUID to client
      webSocket.send(JSON.stringify({
        type: "uuid",
        uuid: userUUID
      }));
      
      // Handle the tunnel
      await handleTunnel(webSocket, selectedProxy, env);
      
      return new Response(null, {
        status: 101,
        webSocket: client,
        headers: {
          "X-User-UUID": userUUID
        }
      });
    }
    
    // Health check endpoint
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({
        status: "ok",
        timestamp: new Date().toISOString()
      }), {
        headers: {
          "Content-Type": "application/json"
        }
      });
    }
    
    return new Response("Not Found", { status: 404 });
  }
};

// Helper functions
function validateUUID(uuid) {
  const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return regex.test(uuid);
}

async function handleTunnel(webSocket, proxyAddress, env) {
  const [proxyIP, proxyPort] = proxyAddress.split(":");
  
  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, "", log);
  
  let remoteSocketWrapper = { value: null };
  let isDNS = false;
  
  readableWebSocketStream.pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        if (isDNS) {
          // Handle DNS (simplified)
          return;
        }
        
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }
        
        // Detect protocol and get destination
        const protocol = await protocolSniffer(chunk);
        let protocolHeader;
        
        if (protocol === "trojan") {
          protocolHeader = readTrojanHeader(chunk);
        } else if (protocol === "vmess") {
          protocolHeader = readVmessHeader(chunk);
        } else if (protocol === "ss") {
          protocolHeader = readSsHeader(chunk);
        } else {
          throw new Error("Unknown Protocol!");
        }
        
        if (protocolHeader.hasError) {
          throw new Error(protocolHeader.message);
        }
        
        addressLog = protocolHeader.addressRemote;
        portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
        
        if (protocolHeader.isUDP) {
          // Handle UDP (simplified)
          return;
        }
        
        // Connect to destination through proxy
        const tcpSocket = connect({
          hostname: proxyIP,
          port: parseInt(proxyPort) || 443,
        });
        
        remoteSocketWrapper.value = tcpSocket;
        log(`connected to ${proxyIP}:${proxyPort}`);
        
        const writer = tcpSocket.writable.getWriter();
        await writer.write(protocolHeader.rawClientData);
        writer.releaseLock();
        
        // Forward data between WebSocket and TCP socket
        await forwardData(tcpSocket, webSocket, protocolHeader.version, log);
      },
      close() {
        log(`WebSocket connection closed`);
      },
      abort(reason) {
        log(`WebSocket connection aborted: ${reason}`);
      }
    })
  ).catch(err => {
    log(`Error in tunnel: ${err}`);
  });
}

async function forwardData(tcpSocket, webSocket, responseHeader, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  
  await tcpSocket.readable.pipeTo(
    new WritableStream({
      start() {},
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState === 1) { // WebSocket.OPEN
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        }
      },
      close() {
        log(`TCP connection closed with hasIncomingData: ${hasIncomingData}`);
      },
      abort(reason) {
        console.error(`TCP connection aborted: ${reason}`);
      }
    })
  ).catch(error => {
    console.error(`Error forwarding data: ${error}`);
    safeCloseWebSocket(webSocket);
  });
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      
      webSocketServer.addEventListener("error", (err) => {
        log("WebSocket error");
        controller.error(err);
      });
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream canceled: ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  
  return stream;
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) {
      socket.close();
    }
  } catch (error) {
    console.error("Error closing WebSocket:", error);
  }
}

// Protocol detection functions
async function protocolSniffer(buffer) {
  // Check for Trojan
  if (buffer.byteLength >= 56) {
    const crlf = new Uint8Array(buffer.slice(56, 58));
    if (crlf[0] === 0x0d && crlf[1] === 0x0a) {
      return "trojan";
    }
  }
  
  // Check for Vmess
  if (buffer.byteLength >= 17) {
    const uuidBytes = new Uint8Array(buffer.slice(1, 17));
    const uuidHex = Array.from(uuidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuidHex)) {
      return "vmess";
    }
  }
  
  // Default to Shadowsocks
  return "ss";
}

// Header reading functions
function readTrojanHeader(buffer) {
  const dataBuffer = buffer.slice(56);
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  const isUDP = cmd === 3;
  
  let addressType = view.getUint8(1);
  let addressValueIndex = 2;
  let addressValue = "";
  
  switch (addressType) {
    case 1: // IPv4
      addressValue = Array.from(dataBuffer.slice(addressValueIndex, addressValueIndex + 4))
        .join(".");
      break;
    case 3: // Domain
      const addressLength = view.getUint8(addressValueIndex);
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 4: // IPv6
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + 16));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
  }
  
  const portIndex = addressValueIndex + (addressType === 3 ? 
    new Uint8Array(dataBuffer.slice(addressValueIndex - 1, addressValueIndex))[0] + 1 : 
    addressType === 1 ? 4 : 16);
  const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  
  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote: portRemote,
    rawClientData: dataBuffer.slice(portIndex + 2),
    version: null,
    isUDP: isUDP
  };
}

function readVmessHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  const isUDP = cmd === 2;
  
  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  
  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressValue = "";
  
  switch (addressType) {
    case 1: // IPv4
      addressValue = Array.from(buffer.slice(addressIndex + 1, addressIndex + 5))
        .join(".");
      break;
    case 2: // Domain
      const addressLength = new Uint8Array(buffer.slice(addressIndex + 1, addressIndex + 2))[0];
      addressValue = new TextDecoder().decode(
        buffer.slice(addressIndex + 2, addressIndex + 2 + addressLength)
      );
      break;
    case 3: // IPv6
      const dataView = new DataView(buffer.slice(addressIndex + 1, addressIndex + 17));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
  }
  
  const rawDataIndex = addressType === 2 ? 
    addressIndex + 2 + (new Uint8Array(buffer.slice(addressIndex + 1, addressIndex + 2))[0]) :
    addressType === 1 ? addressIndex + 5 : addressIndex + 17;
  
  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote: portRemote,
    rawClientData: buffer.slice(rawDataIndex),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP
  };
}

function readSsHeader(buffer) {
  const view = new DataView(buffer);
  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";
  
  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = Array.from(buffer.slice(addressValueIndex, addressValueIndex + addressLength))
        .join(".");
      break;
    case 3: // Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        buffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 4: // IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
  }
  
  const portIndex = addressValueIndex + addressLength;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: buffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote === 53
  };
}
