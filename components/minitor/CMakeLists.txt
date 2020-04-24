cmake_minimum_required(VERSION 3.5)

set(COMPONENT_REQUIRES wolfssl)

set(COMPONENT_SRCDIRS "./src/" "./src/structures/")

set(COMPONENT_ADD_INCLUDEDIRS "./include/")

register_component()
