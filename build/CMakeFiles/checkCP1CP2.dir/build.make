# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rgnoh/CompNet/lab2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rgnoh/CompNet/lab2/build

# Include any dependencies generated for this target.
include CMakeFiles/checkCP1CP2.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/checkCP1CP2.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/checkCP1CP2.dir/flags.make

CMakeFiles/checkCP1CP2.dir/src/device.o: CMakeFiles/checkCP1CP2.dir/flags.make
CMakeFiles/checkCP1CP2.dir/src/device.o: ../src/device.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/checkCP1CP2.dir/src/device.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/checkCP1CP2.dir/src/device.o   -c /home/rgnoh/CompNet/lab2/src/device.c

CMakeFiles/checkCP1CP2.dir/src/device.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/checkCP1CP2.dir/src/device.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/device.c > CMakeFiles/checkCP1CP2.dir/src/device.i

CMakeFiles/checkCP1CP2.dir/src/device.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/checkCP1CP2.dir/src/device.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/device.c -o CMakeFiles/checkCP1CP2.dir/src/device.s

CMakeFiles/checkCP1CP2.dir/src/device.o.requires:

.PHONY : CMakeFiles/checkCP1CP2.dir/src/device.o.requires

CMakeFiles/checkCP1CP2.dir/src/device.o.provides: CMakeFiles/checkCP1CP2.dir/src/device.o.requires
	$(MAKE) -f CMakeFiles/checkCP1CP2.dir/build.make CMakeFiles/checkCP1CP2.dir/src/device.o.provides.build
.PHONY : CMakeFiles/checkCP1CP2.dir/src/device.o.provides

CMakeFiles/checkCP1CP2.dir/src/device.o.provides.build: CMakeFiles/checkCP1CP2.dir/src/device.o


CMakeFiles/checkCP1CP2.dir/src/inc.o: CMakeFiles/checkCP1CP2.dir/flags.make
CMakeFiles/checkCP1CP2.dir/src/inc.o: ../src/inc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/checkCP1CP2.dir/src/inc.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/checkCP1CP2.dir/src/inc.o   -c /home/rgnoh/CompNet/lab2/src/inc.c

CMakeFiles/checkCP1CP2.dir/src/inc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/checkCP1CP2.dir/src/inc.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/inc.c > CMakeFiles/checkCP1CP2.dir/src/inc.i

CMakeFiles/checkCP1CP2.dir/src/inc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/checkCP1CP2.dir/src/inc.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/inc.c -o CMakeFiles/checkCP1CP2.dir/src/inc.s

CMakeFiles/checkCP1CP2.dir/src/inc.o.requires:

.PHONY : CMakeFiles/checkCP1CP2.dir/src/inc.o.requires

CMakeFiles/checkCP1CP2.dir/src/inc.o.provides: CMakeFiles/checkCP1CP2.dir/src/inc.o.requires
	$(MAKE) -f CMakeFiles/checkCP1CP2.dir/build.make CMakeFiles/checkCP1CP2.dir/src/inc.o.provides.build
.PHONY : CMakeFiles/checkCP1CP2.dir/src/inc.o.provides

CMakeFiles/checkCP1CP2.dir/src/inc.o.provides.build: CMakeFiles/checkCP1CP2.dir/src/inc.o


CMakeFiles/checkCP1CP2.dir/src/ip.o: CMakeFiles/checkCP1CP2.dir/flags.make
CMakeFiles/checkCP1CP2.dir/src/ip.o: ../src/ip.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/checkCP1CP2.dir/src/ip.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/checkCP1CP2.dir/src/ip.o   -c /home/rgnoh/CompNet/lab2/src/ip.c

CMakeFiles/checkCP1CP2.dir/src/ip.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/checkCP1CP2.dir/src/ip.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/ip.c > CMakeFiles/checkCP1CP2.dir/src/ip.i

CMakeFiles/checkCP1CP2.dir/src/ip.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/checkCP1CP2.dir/src/ip.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/ip.c -o CMakeFiles/checkCP1CP2.dir/src/ip.s

CMakeFiles/checkCP1CP2.dir/src/ip.o.requires:

.PHONY : CMakeFiles/checkCP1CP2.dir/src/ip.o.requires

CMakeFiles/checkCP1CP2.dir/src/ip.o.provides: CMakeFiles/checkCP1CP2.dir/src/ip.o.requires
	$(MAKE) -f CMakeFiles/checkCP1CP2.dir/build.make CMakeFiles/checkCP1CP2.dir/src/ip.o.provides.build
.PHONY : CMakeFiles/checkCP1CP2.dir/src/ip.o.provides

CMakeFiles/checkCP1CP2.dir/src/ip.o.provides.build: CMakeFiles/checkCP1CP2.dir/src/ip.o


CMakeFiles/checkCP1CP2.dir/src/packetio.o: CMakeFiles/checkCP1CP2.dir/flags.make
CMakeFiles/checkCP1CP2.dir/src/packetio.o: ../src/packetio.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/checkCP1CP2.dir/src/packetio.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/checkCP1CP2.dir/src/packetio.o   -c /home/rgnoh/CompNet/lab2/src/packetio.c

CMakeFiles/checkCP1CP2.dir/src/packetio.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/checkCP1CP2.dir/src/packetio.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/src/packetio.c > CMakeFiles/checkCP1CP2.dir/src/packetio.i

CMakeFiles/checkCP1CP2.dir/src/packetio.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/checkCP1CP2.dir/src/packetio.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/src/packetio.c -o CMakeFiles/checkCP1CP2.dir/src/packetio.s

CMakeFiles/checkCP1CP2.dir/src/packetio.o.requires:

.PHONY : CMakeFiles/checkCP1CP2.dir/src/packetio.o.requires

CMakeFiles/checkCP1CP2.dir/src/packetio.o.provides: CMakeFiles/checkCP1CP2.dir/src/packetio.o.requires
	$(MAKE) -f CMakeFiles/checkCP1CP2.dir/build.make CMakeFiles/checkCP1CP2.dir/src/packetio.o.provides.build
.PHONY : CMakeFiles/checkCP1CP2.dir/src/packetio.o.provides

CMakeFiles/checkCP1CP2.dir/src/packetio.o.provides.build: CMakeFiles/checkCP1CP2.dir/src/packetio.o


CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o: CMakeFiles/checkCP1CP2.dir/flags.make
CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o: ../check/checkCP1CP2.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o   -c /home/rgnoh/CompNet/lab2/check/checkCP1CP2.c

CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/rgnoh/CompNet/lab2/check/checkCP1CP2.c > CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.i

CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/rgnoh/CompNet/lab2/check/checkCP1CP2.c -o CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.s

CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.requires:

.PHONY : CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.requires

CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.provides: CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.requires
	$(MAKE) -f CMakeFiles/checkCP1CP2.dir/build.make CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.provides.build
.PHONY : CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.provides

CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.provides.build: CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o


# Object files for target checkCP1CP2
checkCP1CP2_OBJECTS = \
"CMakeFiles/checkCP1CP2.dir/src/device.o" \
"CMakeFiles/checkCP1CP2.dir/src/inc.o" \
"CMakeFiles/checkCP1CP2.dir/src/ip.o" \
"CMakeFiles/checkCP1CP2.dir/src/packetio.o" \
"CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o"

# External object files for target checkCP1CP2
checkCP1CP2_EXTERNAL_OBJECTS =

checkCP1CP2: CMakeFiles/checkCP1CP2.dir/src/device.o
checkCP1CP2: CMakeFiles/checkCP1CP2.dir/src/inc.o
checkCP1CP2: CMakeFiles/checkCP1CP2.dir/src/ip.o
checkCP1CP2: CMakeFiles/checkCP1CP2.dir/src/packetio.o
checkCP1CP2: CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o
checkCP1CP2: CMakeFiles/checkCP1CP2.dir/build.make
checkCP1CP2: CMakeFiles/checkCP1CP2.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rgnoh/CompNet/lab2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable checkCP1CP2"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/checkCP1CP2.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/checkCP1CP2.dir/build: checkCP1CP2

.PHONY : CMakeFiles/checkCP1CP2.dir/build

CMakeFiles/checkCP1CP2.dir/requires: CMakeFiles/checkCP1CP2.dir/src/device.o.requires
CMakeFiles/checkCP1CP2.dir/requires: CMakeFiles/checkCP1CP2.dir/src/inc.o.requires
CMakeFiles/checkCP1CP2.dir/requires: CMakeFiles/checkCP1CP2.dir/src/ip.o.requires
CMakeFiles/checkCP1CP2.dir/requires: CMakeFiles/checkCP1CP2.dir/src/packetio.o.requires
CMakeFiles/checkCP1CP2.dir/requires: CMakeFiles/checkCP1CP2.dir/check/checkCP1CP2.o.requires

.PHONY : CMakeFiles/checkCP1CP2.dir/requires

CMakeFiles/checkCP1CP2.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/checkCP1CP2.dir/cmake_clean.cmake
.PHONY : CMakeFiles/checkCP1CP2.dir/clean

CMakeFiles/checkCP1CP2.dir/depend:
	cd /home/rgnoh/CompNet/lab2/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rgnoh/CompNet/lab2 /home/rgnoh/CompNet/lab2 /home/rgnoh/CompNet/lab2/build /home/rgnoh/CompNet/lab2/build /home/rgnoh/CompNet/lab2/build/CMakeFiles/checkCP1CP2.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/checkCP1CP2.dir/depend

