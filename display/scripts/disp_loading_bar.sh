#!/usr/bin/bash

LINE=$1

while true; do
  sudo disp_custom_msg.sh --line${LINE} "|***           |"
  sudo disp_custom_msg.sh --line${LINE} "| ***          |"
  sudo disp_custom_msg.sh --line${LINE} "|  ***         |"
  sudo disp_custom_msg.sh --line${LINE} "|   ***        |"
  sudo disp_custom_msg.sh --line${LINE} "|    ***       |"
  sudo disp_custom_msg.sh --line${LINE} "|     ***      |"
  sudo disp_custom_msg.sh --line${LINE} "|      ***     |"
  sudo disp_custom_msg.sh --line${LINE} "|       ***    |"
  sudo disp_custom_msg.sh --line${LINE} "|        ***   |"
  sudo disp_custom_msg.sh --line${LINE} "|         ***  |"
  sudo disp_custom_msg.sh --line${LINE} "|           ***|"
  sudo disp_custom_msg.sh --line${LINE} "|*           **|"
  sudo disp_custom_msg.sh --line${LINE} "|**           *|"
done
