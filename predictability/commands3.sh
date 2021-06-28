#!/bin/bash -x

flow_categories=( "Classic"  "PortLess" "SubnetLess8" "SubnetLess16" "NSLookup" "DomainNoDigit" )
# for flow_cate in "${flow_categories[@]}"
# do
#     mkdir -p results/yourthing/11/${flow_cate} results/yourthing/12/${flow_cate}

#     python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/${flow_cate}/output.json
#     python3 plot_data_trans.py results/yourthing/11/${flow_cate}/output.json results/yourthing/11/${flow_cate}

#     python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/${flow_cate}/output.json
#     python3 plot_data_trans.py results/yourthing/12/${flow_cate}/output.json results/yourthing/12/${flow_cate}
# done

curr_dir="/home/robin/yunming"
dataset_dir="/home/robin/datasets/moniotr/iot-idle"
result_idle_dir="/home/robin/yunming/results/moniotr/iot-idle-out"

target_dir=( "uk" )
for tdir in "${target_dir[@]}"
do
    cd ${dataset_dir}
    final_dirs=($(ls -d "${tdir}"/*))

    for dd in "${final_dirs[@]}"
    do
        cd ${curr_dir}
        for flow_cate in "${flow_categories[@]}"
        do
            # echo "${result_idle_dir}/${dd}/${flow_cate}/filter.json"
            mkdir -p ${result_idle_dir}/${dd}/${flow_cate} 
            python3 regular_trace_extract3.py ${flow_cate} /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_idle_dir}/${dd}/${flow_cate}/output.json \
            None None "out" ${result_idle_dir}/${dd}/${flow_cate}/filter.json
            python3 plot_data_trans.py ${result_dir}/${dd}/${flow_cate}/output.json ${result_dir}/${dd}/${flow_cate}
        done
    done
done


curr_dir="/home/robin/yunming"
dataset_dir="/home/robin/datasets/moniotr/iot-data"
result_dir="/home/robin/yunming/results/moniotr/iot-data-in"

target_dir=( "uk" )
for tdir in "${target_dir[@]}"
do
    cd ${dataset_dir}
    final_dirs=($(ls -d "${tdir}"/*/*))

    for dd in "${final_dirs[@]}"
    do
        cd ${curr_dir}
        for flow_cate in "${flow_categories[@]}"
        do
            # echo "${result_idle_dir}/${dd%/*}/${flow_cate}/filter.json"
            mkdir -p ${result_dir}/${dd}/${flow_cate} 
            python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/${flow_cate}/output.json \
            None None "in" ${result_idle_dir}/${dd%/*}/${flow_cate}/filter.json
            python3 plot_data_trans.py ${result_dir}/${dd}/${flow_cate}/output.json ${result_dir}/${dd}/${flow_cate}
        done
    done
done




cd ${curr_dir}