#!/usr/bin/bash

LINE=$1

while true; do
  disp_custom_msg.sh --line${LINE} "|***           |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "| ***          |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|  ***         |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|   ***        |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|    ***       |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|     ***      |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|      ***     |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|       ***    |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|        ***   |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|         ***  |"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|           ***|"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|*           **|"
  sleep 0.1
  disp_custom_msg.sh --line${LINE} "|**           *|"
  sleep 0.1
done
