cmake_minimum_required(VERSION 3.31)
set(CMAKE_CXX_STANDARD 20)
project(gwatch)
FIND_PACKAGE( Boost 1.84 COMPONENTS program_options iostreams REQUIRED )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )
add_executable(gwatch main.cpp VariableWatcher.hpp
)
TARGET_LINK_LIBRARIES( gwatch LINK_PUBLIC ${Boost_LIBRARIES} z bz2)
