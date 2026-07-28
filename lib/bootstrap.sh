#!/usr/bin/env bash

##
# Main framework entry point.
#
# Arguments:
#   All command line arguments.
#
# Returns:
#   Exit status.
##
main() {

    load_constants

    load_configuration

    initialize_logging

    detect_environment

    initialize_runtime

    start_execution "$@"

}