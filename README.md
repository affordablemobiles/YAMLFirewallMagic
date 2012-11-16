# YAMLFirewallMagic

YAMLFirewallMagic is a tool we developed for compiling an easy to read / manipulate YAML format for IPTables rules into pure iptables-save format ready for loading with the iptable-restore command.

## Features

Support for Interface to Firewall rule chains.
Support for Interface to Interface forward chains.
Ability to include files for a NOC environment where you have standard config for all boxes that you want to include into the config for each individual firewall.
