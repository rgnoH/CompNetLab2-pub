# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rgnoh/CompNet/lab2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rgnoh/CompNet/lab2/build

# Include any dependencies generated for this target.
include CMakeFiles/echo_client.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/echo_client.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/echo_client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/echo_client.dir/flags.make

CMakeFiles/echo_client.dir/src/arp.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/arp.o: ../src/arp.c
CMakeFiles/echo_client.dir/src/arp.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/echo_client.dir/src/arp.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/arp.o -MF CMakeFiles/echo_client.dir/src/arp.o.d -o CMakeFiles/echo_client.dir/src/arp.o -c /home/rgnoh/CompNet/lab2/src/arp.c

CMakeFiles/echo_client.dir/src/arp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/arp.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/arp.c > CMakeFiles/echo_client.dir/src/arp.i

CMakeFiles/echo_client.dir/src/arp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/arp.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/arp.c -o CMakeFiles/echo_client.dir/src/arp.s

CMakeFiles/echo_client.dir/src/device.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/device.o: ../src/device.c
CMakeFiles/echo_client.dir/src/device.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/echo_client.dir/src/device.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/device.o -MF CMakeFiles/echo_client.dir/src/device.o.d -o CMakeFiles/echo_client.dir/src/device.o -c /home/rgnoh/CompNet/lab2/src/device.c

CMakeFiles/echo_client.dir/src/device.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/device.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/device.c > CMakeFiles/echo_client.dir/src/device.i

CMakeFiles/echo_client.dir/src/device.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/device.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/device.c -o CMakeFiles/echo_client.dir/src/device.s

CMakeFiles/echo_client.dir/src/inc.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/inc.o: ../src/inc.c
CMakeFiles/echo_client.dir/src/inc.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/echo_client.dir/src/inc.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/inc.o -MF CMakeFiles/echo_client.dir/src/inc.o.d -o CMakeFiles/echo_client.dir/src/inc.o -c /home/rgnoh/CompNet/lab2/src/inc.c

CMakeFiles/echo_client.dir/src/inc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/inc.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/inc.c > CMakeFiles/echo_client.dir/src/inc.i

CMakeFiles/echo_client.dir/src/inc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/inc.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/inc.c -o CMakeFiles/echo_client.dir/src/inc.s

CMakeFiles/echo_client.dir/src/ip.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/ip.o: ../src/ip.c
CMakeFiles/echo_client.dir/src/ip.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/echo_client.dir/src/ip.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/ip.o -MF CMakeFiles/echo_client.dir/src/ip.o.d -o CMakeFiles/echo_client.dir/src/ip.o -c /home/rgnoh/CompNet/lab2/src/ip.c

CMakeFiles/echo_client.dir/src/ip.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/ip.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/ip.c > CMakeFiles/echo_client.dir/src/ip.i

CMakeFiles/echo_client.dir/src/ip.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/ip.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/ip.c -o CMakeFiles/echo_client.dir/src/ip.s

CMakeFiles/echo_client.dir/src/packetio.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/packetio.o: ../src/packetio.c
CMakeFiles/echo_client.dir/src/packetio.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/echo_client.dir/src/packetio.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/packetio.o -MF CMakeFiles/echo_client.dir/src/packetio.o.d -o CMakeFiles/echo_client.dir/src/packetio.o -c /home/rgnoh/CompNet/lab2/src/packetio.c

CMakeFiles/echo_client.dir/src/packetio.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/packetio.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/packetio.c > CMakeFiles/echo_client.dir/src/packetio.i

CMakeFiles/echo_client.dir/src/packetio.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/packetio.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/packetio.c -o CMakeFiles/echo_client.dir/src/packetio.s

CMakeFiles/echo_client.dir/src/socket.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/socket.o: ../src/socket.c
CMakeFiles/echo_client.dir/src/socket.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/echo_client.dir/src/socket.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/socket.o -MF CMakeFiles/echo_client.dir/src/socket.o.d -o CMakeFiles/echo_client.dir/src/socket.o -c /home/rgnoh/CompNet/lab2/src/socket.c

CMakeFiles/echo_client.dir/src/socket.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/socket.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/socket.c > CMakeFiles/echo_client.dir/src/socket.i

CMakeFiles/echo_client.dir/src/socket.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/socket.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/socket.c -o CMakeFiles/echo_client.dir/src/socket.s

CMakeFiles/echo_client.dir/src/tcp.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/tcp.o: ../src/tcp.c
CMakeFiles/echo_client.dir/src/tcp.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/echo_client.dir/src/tcp.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/tcp.o -MF CMakeFiles/echo_client.dir/src/tcp.o.d -o CMakeFiles/echo_client.dir/src/tcp.o -c /home/rgnoh/CompNet/lab2/src/tcp.c

CMakeFiles/echo_client.dir/src/tcp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/tcp.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/tcp.c > CMakeFiles/echo_client.dir/src/tcp.i

CMakeFiles/echo_client.dir/src/tcp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/tcp.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/tcp.c -o CMakeFiles/echo_client.dir/src/tcp.s

CMakeFiles/echo_client.dir/src/unp.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/src/unp.o: ../src/unp.c
CMakeFiles/echo_client.dir/src/unp.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/echo_client.dir/src/unp.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/src/unp.o -MF CMakeFiles/echo_client.dir/src/unp.o.d -o CMakeFiles/echo_client.dir/src/unp.o -c /home/rgnoh/CompNet/lab2/src/unp.c

CMakeFiles/echo_client.dir/src/unp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/src/unp.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/unp.c > CMakeFiles/echo_client.dir/src/unp.i

CMakeFiles/echo_client.dir/src/unp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/src/unp.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/unp.c -o CMakeFiles/echo_client.dir/src/unp.s

CMakeFiles/echo_client.dir/checkpoints/echo_client.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/checkpoints/echo_client.o: ../checkpoints/echo_client.c
CMakeFiles/echo_client.dir/checkpoints/echo_client.o: CMakeFiles/echo_client.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/echo_client.dir/checkpoints/echo_client.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/echo_client.dir/checkpoints/echo_client.o -MF CMakeFiles/echo_client.dir/checkpoints/echo_client.o.d -o CMakeFiles/echo_client.dir/checkpoints/echo_client.o -c /home/rgnoh/CompNet/lab2/checkpoints/echo_client.c

CMakeFiles/echo_client.dir/checkpoints/echo_client.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/checkpoints/echo_client.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/checkpoints/echo_client.c > CMakeFiles/echo_client.dir/checkpoints/echo_client.i

CMakeFiles/echo_client.dir/checkpoints/echo_client.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/checkpoints/echo_client.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/checkpoints/echo_client.c -o CMakeFiles/echo_client.dir/checkpoints/echo_client.s

# Object files for target echo_client
echo_client_OBJECTS = \
"CMakeFiles/echo_client.dir/src/arp.o" \
"CMakeFiles/echo_client.dir/src/device.o" \
"CMakeFiles/echo_client.dir/src/inc.o" \
"CMakeFiles/echo_client.dir/src/ip.o" \
"CMakeFiles/echo_client.dir/src/packetio.o" \
"CMakeFiles/echo_client.dir/src/socket.o" \
"CMakeFiles/echo_client.dir/src/tcp.o" \
"CMakeFiles/echo_client.dir/src/unp.o" \
"CMakeFiles/echo_client.dir/checkpoints/echo_client.o"

# External object files for target echo_client
echo_client_EXTERNAL_OBJECTS =

echo_client: CMakeFiles/echo_client.dir/src/arp.o
echo_client: CMakeFiles/echo_client.dir/src/device.o
echo_client: CMakeFiles/echo_client.dir/src/inc.o
echo_client: CMakeFiles/echo_client.dir/src/ip.o
echo_client: CMakeFiles/echo_client.dir/src/packetio.o
echo_client: CMakeFiles/echo_client.dir/src/socket.o
echo_client: CMakeFiles/echo_client.dir/src/tcp.o
echo_client: CMakeFiles/echo_client.dir/src/unp.o
echo_client: CMakeFiles/echo_client.dir/checkpoints/echo_client.o
echo_client: CMakeFiles/echo_client.dir/build.make
echo_client: CMakeFiles/echo_client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking C executable echo_client"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/echo_client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/echo_client.dir/build: echo_client
.PHONY : CMakeFiles/echo_client.dir/build

CMakeFiles/echo_client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/echo_client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/echo_client.dir/clean

CMakeFiles/echo_client.dir/depend:
	cd /home/rgnoh/CompNet/lab2/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rgnoh/CompNet/lab2 /home/rgnoh/CompNet/lab2 /home/rgnoh/CompNet/lab2/build /home/rgnoh/CompNet/lab2/build /home/rgnoh/CompNet/lab2/build/CMakeFiles/echo_client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/echo_client.dir/depend

