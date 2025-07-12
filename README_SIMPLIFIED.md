# Simplified TCP Server/Client Project

## Project Structure

1. **`unified_server.c`** - A single server that supports both basic echo mode and chat mode
2. **`unified_client.c`** - A single client that can connect to either server mode
3. **`simple_test_client.c`** - A simple test client for automated testing


### Unified Server (`unified_server.c`)
- **Basic Mode**: Simple echo server that responds to client messages
- **Chat Mode**: Multi-client chat server with nicknames and commands
- **Command Line Options**: Choose mode with `./unified_server.exe basic` or `./unified_server.exe chat`

### Unified Client (`unified_client.c`)
- **Basic Mode**: Sends predefined test messages and displays server responses
- **Chat Mode**: Interactive chat client with real-time messaging
- **Command Line Options**: Choose mode with `./unified_client.exe basic` or `./unified_client.exe chat`

### Simple Test Client (`simple_test_client.c`)
- Automated testing client that sends test messages and exits
- Useful for testing server functionality

### How to Use:
Run unified_client and unified_server in separate terminals with your desired mode.
Both the client and server use the loopback address 127.0.0.1 and different ports on the same deivce and can mimic a basic group chat.


**Chat Commands:**
   - `/nick <name>` - Change your nickname
   - `/list` - List connected clients
   - `/quit` - Disconnect from chat

