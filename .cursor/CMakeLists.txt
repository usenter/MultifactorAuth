cmake_minimum_required(VERSION 3.10)
project(TCPserver C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# List all executables and their sources
add_executable(tcp_server ../tcp_server.c)
add_executable(tcp_client ../tcp_client.c)
add_executable(multi_client_test ../multi_client_test.c)
add_executable(client_to_client_server ../client_to_client_server.c)
add_executable(chat_client ../chat_client.c)

# Link ws2_32 for Windows networking
if (WIN32)
    target_link_libraries(tcp_server ws2_32)
    target_link_libraries(tcp_client ws2_32)
    target_link_libraries(multi_client_test ws2_32)
    target_link_libraries(client_to_client_server ws2_32)
    target_link_libraries(chat_client ws2_32)
endif() 