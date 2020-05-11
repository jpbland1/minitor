cmake_minimum_required(VERSION 3.5)

set(COMPONENT_REQUIRES wolfssl esp32-idf-sqlite3)

set(COMPONENT_SRCDIRS "./src/" "./src/structures/ ./src/models")

set(COMPONENT_ADD_INCLUDEDIRS "./include/")

register_component()
