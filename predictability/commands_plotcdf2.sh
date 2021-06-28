#!/bin/bash -x

flow_categories=( "Classic"  "PortLess" "SubnetLess8" "SubnetLess16" "NSLookup" "DomainNoDigit" )
for flow_cate in "${flow_categories[@]}"
do
	python3 find_regular_flows.py /home/robin/datasets/yourthings/devices.json results/yourthing/11/${flow_cate}/output.json results/yourthing
	python3 find_regular_flows.py /home/robin/datasets/yourthings/devices.json results/yourthing/12/${flow_cate}/output.json results/yourthing
done

python3 plot_regular2.py results/yourthing results/yourthing


curr_dir="/home/robin/yunming"
dataset_dir="/home/robin/datasets/moniotr/iot-data"
result_dir="/home/robin/yunming/results/moniotr/iot-data"

target_dir=( "uk"  "us" )
for tdir in "${target_dir[@]}"
do
    cd ${dataset_dir}
    final_dirs=($(ls -d "${target_dir}"/*/*))

    for dd in "${final_dirs[@]}"
    do
        cd ${curr_dir}
		for flow_cate in "${flow_categories[@]}"
		do
			mkdir -p ${result_dir}/${dd}/${flow_cate}
			python3 find_regular_flows.py /home/robin/datasets/moniotr/devices.json ${result_dir}/${dd}/${flow_cate}/output.json ${result_dir} 
		done
    done
done

cd ${curr_dir}
python3 plot_regular2.py ${result_dir} ${result_dir}


dataset_dir="/home/robin/datasets/moniotr/iot-idle"
result_dir="/home/robin/yunming/results/moniotr/iot-idle"

target_dir=( "uk"  "us" )
for tdir in "${target_dir[@]}"
do
    cd ${dataset_dir}
    final_dirs=($(ls -d "${target_dir}"/*))

    for dd in "${final_dirs[@]}"
    do
        cd ${curr_dir}
		for flow_cate in "${flow_categories[@]}"
		do
			mkdir -p ${result_dir}/${dd}/${flow_cate}
			python3 find_regular_flows.py /home/robin/datasets/moniotr/devices.json ${result_dir}/${dd}/${flow_cate}/output.json ${result_dir} 
		done
    done
done

cd ${curr_dir}
python3 plot_regular2.py ${result_dir} ${result_dir}
