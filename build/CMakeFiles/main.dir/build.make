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
include CMakeFiles/main.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/main.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/main.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/main.dir/flags.make

CMakeFiles/main.dir/src/arp.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/arp.o: ../src/arp.c
CMakeFiles/main.dir/src/arp.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/main.dir/src/arp.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/arp.o -MF CMakeFiles/main.dir/src/arp.o.d -o CMakeFiles/main.dir/src/arp.o -c /home/rgnoh/CompNet/lab2/src/arp.c

CMakeFiles/main.dir/src/arp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/arp.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/arp.c > CMakeFiles/main.dir/src/arp.i

CMakeFiles/main.dir/src/arp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/arp.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/arp.c -o CMakeFiles/main.dir/src/arp.s

CMakeFiles/main.dir/src/device.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/device.o: ../src/device.c
CMakeFiles/main.dir/src/device.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/main.dir/src/device.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/device.o -MF CMakeFiles/main.dir/src/device.o.d -o CMakeFiles/main.dir/src/device.o -c /home/rgnoh/CompNet/lab2/src/device.c

CMakeFiles/main.dir/src/device.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/device.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/device.c > CMakeFiles/main.dir/src/device.i

CMakeFiles/main.dir/src/device.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/device.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/device.c -o CMakeFiles/main.dir/src/device.s

CMakeFiles/main.dir/src/inc.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/inc.o: ../src/inc.c
CMakeFiles/main.dir/src/inc.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/main.dir/src/inc.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/inc.o -MF CMakeFiles/main.dir/src/inc.o.d -o CMakeFiles/main.dir/src/inc.o -c /home/rgnoh/CompNet/lab2/src/inc.c

CMakeFiles/main.dir/src/inc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/inc.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/inc.c > CMakeFiles/main.dir/src/inc.i

CMakeFiles/main.dir/src/inc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/inc.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/inc.c -o CMakeFiles/main.dir/src/inc.s

CMakeFiles/main.dir/src/ip.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/ip.o: ../src/ip.c
CMakeFiles/main.dir/src/ip.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/main.dir/src/ip.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/ip.o -MF CMakeFiles/main.dir/src/ip.o.d -o CMakeFiles/main.dir/src/ip.o -c /home/rgnoh/CompNet/lab2/src/ip.c

CMakeFiles/main.dir/src/ip.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/ip.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/ip.c > CMakeFiles/main.dir/src/ip.i

CMakeFiles/main.dir/src/ip.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/ip.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/ip.c -o CMakeFiles/main.dir/src/ip.s

CMakeFiles/main.dir/src/packetio.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/packetio.o: ../src/packetio.c
CMakeFiles/main.dir/src/packetio.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/main.dir/src/packetio.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/packetio.o -MF CMakeFiles/main.dir/src/packetio.o.d -o CMakeFiles/main.dir/src/packetio.o -c /home/rgnoh/CompNet/lab2/src/packetio.c

CMakeFiles/main.dir/src/packetio.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/packetio.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/packetio.c > CMakeFiles/main.dir/src/packetio.i

CMakeFiles/main.dir/src/packetio.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/packetio.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/packetio.c -o CMakeFiles/main.dir/src/packetio.s

CMakeFiles/main.dir/src/socket.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/socket.o: ../src/socket.c
CMakeFiles/main.dir/src/socket.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/main.dir/src/socket.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/socket.o -MF CMakeFiles/main.dir/src/socket.o.d -o CMakeFiles/main.dir/src/socket.o -c /home/rgnoh/CompNet/lab2/src/socket.c

CMakeFiles/main.dir/src/socket.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/socket.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/socket.c > CMakeFiles/main.dir/src/socket.i

CMakeFiles/main.dir/src/socket.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/socket.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/socket.c -o CMakeFiles/main.dir/src/socket.s

CMakeFiles/main.dir/src/tcp.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/tcp.o: ../src/tcp.c
CMakeFiles/main.dir/src/tcp.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/main.dir/src/tcp.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/tcp.o -MF CMakeFiles/main.dir/src/tcp.o.d -o CMakeFiles/main.dir/src/tcp.o -c /home/rgnoh/CompNet/lab2/src/tcp.c

CMakeFiles/main.dir/src/tcp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/tcp.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/tcp.c > CMakeFiles/main.dir/src/tcp.i

CMakeFiles/main.dir/src/tcp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/tcp.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/tcp.c -o CMakeFiles/main.dir/src/tcp.s

CMakeFiles/main.dir/src/unp.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/unp.o: ../src/unp.c
CMakeFiles/main.dir/src/unp.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/main.dir/src/unp.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/src/unp.o -MF CMakeFiles/main.dir/src/unp.o.d -o CMakeFiles/main.dir/src/unp.o -c /home/rgnoh/CompNet/lab2/src/unp.c

CMakeFiles/main.dir/src/unp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/unp.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/unp.c > CMakeFiles/main.dir/src/unp.i

CMakeFiles/main.dir/src/unp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/unp.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/unp.c -o CMakeFiles/main.dir/src/unp.s

CMakeFiles/main.dir/check/main.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/check/main.o: ../check/main.c
CMakeFiles/main.dir/check/main.o: CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/main.dir/check/main.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/main.dir/check/main.o -MF CMakeFiles/main.dir/check/main.o.d -o CMakeFiles/main.dir/check/main.o -c /home/rgnoh/CompNet/lab2/check/main.c

CMakeFiles/main.dir/check/main.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/check/main.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/check/main.c > CMakeFiles/main.dir/check/main.i

CMakeFiles/main.dir/check/main.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/check/main.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/check/main.c -o CMakeFiles/main.dir/check/main.s

# Object files for target main
main_OBJECTS = \
"CMakeFiles/main.dir/src/arp.o" \
"CMakeFiles/main.dir/src/device.o" \
"CMakeFiles/main.dir/src/inc.o" \
"CMakeFiles/main.dir/src/ip.o" \
"CMakeFiles/main.dir/src/packetio.o" \
"CMakeFiles/main.dir/src/socket.o" \
"CMakeFiles/main.dir/src/tcp.o" \
"CMakeFiles/main.dir/src/unp.o" \
"CMakeFiles/main.dir/check/main.o"

# External object files for target main
main_EXTERNAL_OBJECTS =

main: CMakeFiles/main.dir/src/arp.o
main: CMakeFiles/main.dir/src/device.o
main: CMakeFiles/main.dir/src/inc.o
main: CMakeFiles/main.dir/src/ip.o
main: CMakeFiles/main.dir/src/packetio.o
main: CMakeFiles/main.dir/src/socket.o
main: CMakeFiles/main.dir/src/tcp.o
main: CMakeFiles/main.dir/src/unp.o
main: CMakeFiles/main.dir/check/main.o
main: CMakeFiles/main.dir/build.make
main: CMakeFiles/main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking C executable main"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/main.dir/build: main
.PHONY : CMakeFiles/main.dir/build

CMakeFiles/main.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/main.dir/cmake_clean.cmake
.PHONY : CMakeFiles/main.dir/clean

CMakeFiles/main.dir/depend:
	cd /home/rgnoh/CompNet/lab2/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rgnoh/CompNet/lab2 /home/rgnoh/CompNet/lab2 /home/rgnoh/CompNet/lab2/build /home/rgnoh/CompNet/lab2/build /home/rgnoh/CompNet/lab2/build/CMakeFiles/main.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/main.dir/depend

