#!/bin/bash -x

python3 find_regular_flows.py /home/robin/datasets/yourthings/devices.json results/yourthing-onlytcpudp/11/results/output.json results/yourthing-onlytcpudp
python3 find_regular_flows.py /home/robin/datasets/yourthings/devices.json results/yourthing-onlytcpudp/11/results_noport/output.json results/yourthing-onlytcpudp
python3 find_regular_flows.py /home/robin/datasets/yourthings/devices.json results/yourthing-onlytcpudp/12/results/output.json results/yourthing-onlytcpudp
python3 find_regular_flows.py /home/robin/datasets/yourthings/devices.json results/yourthing-onlytcpudp/12/results_noport/output.json results/yourthing-onlytcpudp
python3 plot_regular.py results/yourthing-onlytcpudp results/yourthing-onlytcpudp

curr_dir="/home/robin/yunming"
dataset_dir="/home/robin/datasets/moniotr/iot-data"
result_dir="/home/robin/yunming/results/moniotr-onlytcpudp/iot-data"

target_dir=( "uk"  "us" )
for tdir in "${target_dir[@]}"
do
    cd ${dataset_dir}
    final_dirs=($(ls -d "${target_dir}"/*/*))

    for dd in "${final_dirs[@]}"
    do
        cd ${curr_dir}
        mkdir -p ${result_dir}/${dd}/results 
        mkdir -p ${result_dir}/${dd}/results_noport 
        python3 find_regular_flows.py /home/robin/datasets/moniotr/devices.json ${result_dir}/${dd}/results/output.json ${result_dir}
        python3 find_regular_flows.py /home/robin/datasets/moniotr/devices.json ${result_dir}/${dd}/results_noport/output.json ${result_dir}
    done
done

cd ${curr_dir}
python3 plot_regular.py ${result_dir} ${result_dir}


dataset_dir="/home/robin/datasets/moniotr/iot-idle"
result_dir="/home/robin/yunming/results/moniotr-onlytcpudp/iot-idle"

target_dir=( "uk"  "us" )
for tdir in "${target_dir[@]}"
do
    cd ${dataset_dir}
    final_dirs=($(ls -d "${target_dir}"/*))

    for dd in "${final_dirs[@]}"
    do
        cd ${curr_dir}
        mkdir -p ${result_dir}/${dd}/results 
        mkdir -p ${result_dir}/${dd}/results_noport
        python3 find_regular_flows.py /home/robin/datasets/moniotr/devices.json ${result_dir}/${dd}/results/output.json ${result_dir}
        python3 find_regular_flows.py /home/robin/datasets/moniotr/devices.json ${result_dir}/${dd}/results_noport/output.json ${result_dir}
    done
done

cd ${curr_dir}
python3 plot_regular.py ${result_dir} ${result_dir}
