#!/usr/bin/bash

LINE=$1

while true; do
  sudo disp_custom_msg.sh --line${LINE} "|***           |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "| ***          |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|  ***         |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|   ***        |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|    ***       |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|     ***      |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|      ***     |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|       ***    |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|        ***   |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|         ***  |"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|           ***|"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|*           **|"
  sleep 0.5
  sudo disp_custom_msg.sh --line${LINE} "|**           *|"
  sleep 0.5
done
