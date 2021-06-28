#!/bin/bash -x

# mkdir -p results/yourthing/11/results results/yourthing/11/results_noport results/yourthing/12/results results/yourthing/12/results_noport

# python3 regular_trace_extract.py True /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300,/home/robin/datasets/yourthings/11/eth1-20180411.0030.1523424600,/home/robin/datasets/yourthings/11/eth1-20180411.0035.1523424900,/home/robin/datasets/yourthings/11/eth1-20180411.0040.1523425200,/home/robin/datasets/yourthings/11/eth1-20180411.0045.1523425500,/home/robin/datasets/yourthings/11/eth1-20180411.0050.1523425800,/home/robin/datasets/yourthings/11/eth1-20180411.0055.1523426100 results/yourthing/11/results/output.json
# python3 plot_data_trans.py results/yourthing/11/results/output.json results/yourthing/11/results

# python3 regular_trace_extract.py False /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300,/home/robin/datasets/yourthings/11/eth1-20180411.0030.1523424600,/home/robin/datasets/yourthings/11/eth1-20180411.0035.1523424900,/home/robin/datasets/yourthings/11/eth1-20180411.0040.1523425200,/home/robin/datasets/yourthings/11/eth1-20180411.0045.1523425500,/home/robin/datasets/yourthings/11/eth1-20180411.0050.1523425800,/home/robin/datasets/yourthings/11/eth1-20180411.0055.1523426100 results/yourthing/11/results_noport/output.json
# python3 plot_data_trans.py results/yourthing/11/results_noport/output.json results/yourthing/11/results_noport

# python3 regular_trace_extract.py True /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700,/home/robin/datasets/yourthings/12/eth1-20180412.0030.1523511000,/home/robin/datasets/yourthings/12/eth1-20180412.0035.1523511300,/home/robin/datasets/yourthings/12/eth1-20180412.0040.1523511600,/home/robin/datasets/yourthings/12/eth1-20180412.0045.1523511900,/home/robin/datasets/yourthings/12/eth1-20180412.0050.1523512200,/home/robin/datasets/yourthings/12/eth1-20180412.0055.1523512500 results/yourthing/12/results/output.json
# python3 plot_data_trans.py results/yourthing/12/results/output.json results/yourthing/12/results

# python3 regular_trace_extract.py False /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700,/home/robin/datasets/yourthings/12/eth1-20180412.0030.1523511000,/home/robin/datasets/yourthings/12/eth1-20180412.0035.1523511300,/home/robin/datasets/yourthings/12/eth1-20180412.0040.1523511600,/home/robin/datasets/yourthings/12/eth1-20180412.0045.1523511900,/home/robin/datasets/yourthings/12/eth1-20180412.0050.1523512200,/home/robin/datasets/yourthings/12/eth1-20180412.0055.1523512500 results/yourthing/12/results_noport/output.json
# python3 plot_data_trans.py results/yourthing/12/results_noport/output.json results/yourthing/12/results_noport

flow_categories=( "Classic"  "PortLess" "SubnetLess8" "SubnetLess16" "NSLookup" "DomainNoDigit" )
for flow_cate in "${flow_categories[@]}"
do
    mkdir -p results/yourthing/11/${flow_cate} results/yourthing/12/${flow_cate}

    python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/${flow_cate}/output.json
    python3 plot_data_trans.py results/yourthing/11/${flow_cate}/output.json results/yourthing/11/${flow_cate}

    python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/${flow_cate}/output.json
    python3 plot_data_trans.py results/yourthing/12/${flow_cate}/output.json results/yourthing/12/${flow_cate}
done

# python3 regular_trace_extract2.py Classic /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/Classic/output.json
# python3 plot_data_trans.py results/yourthing/11/Classic/output.json results/yourthing/11/Classic

# python3 regular_trace_extract2.py PortLess /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/PortLess/output.json
# python3 plot_data_trans.py results/yourthing/11/PortLess/output.json results/yourthing/11/PortLess

# python3 regular_trace_extract2.py SubnetLess8 /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/SubnetLess8/output.json
# python3 plot_data_trans.py results/yourthing/11/SubnetLess8/output.json results/yourthing/11/SubnetLess8

# python3 regular_trace_extract2.py SubnetLess16 /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/SubnetLess16/output.json
# python3 plot_data_trans.py results/yourthing/11/SubnetLess16/output.json results/yourthing/11/SubnetLess16

# python3 regular_trace_extract2.py NSLookup /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800,/home/robin/datasets/yourthings/11/eth1-20180411.0005.1523423100,/home/robin/datasets/yourthings/11/eth1-20180411.0010.1523423400,/home/robin/datasets/yourthings/11/eth1-20180411.0015.1523423700,/home/robin/datasets/yourthings/11/eth1-20180411.0020.1523424000,/home/robin/datasets/yourthings/11/eth1-20180411.0025.1523424300 results/yourthing/11/NSLookup/output.json
# python3 plot_data_trans.py results/yourthing/11/NSLookup/output.json results/yourthing/11/NSLookup


# python3 regular_trace_extract2.py Classic /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/Classic/output.json
# python3 plot_data_trans.py results/yourthing/12/Classic/output.json results/yourthing/12/Classic

# python3 regular_trace_extract2.py PortLess /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/PortLess/output.json
# python3 plot_data_trans.py results/yourthing/12/Classic/output.json results/yourthing/12/Classic

# python3 regular_trace_extract2.py SubnetLess8 /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/SubnetLess8/output.json
# python3 plot_data_trans.py results/yourthing/12/Classic/output.json results/yourthing/12/Classic

# python3 regular_trace_extract2.py SubnetLess16 /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/SubnetLess16/output.json
# python3 plot_data_trans.py results/yourthing/12/Classic/output.json results/yourthing/12/Classic

# python3 regular_trace_extract2.py NSLookup /home/robin/datasets/yourthings/devices.json /home/robin/datasets/yourthings/12/eth1-20180412.0000.1523509200,/home/robin/datasets/yourthings/12/eth1-20180412.0005.1523509500,/home/robin/datasets/yourthings/12/eth1-20180412.0010.1523509800,/home/robin/datasets/yourthings/12/eth1-20180412.0015.1523510100,/home/robin/datasets/yourthings/12/eth1-20180412.0020.1523510400,/home/robin/datasets/yourthings/12/eth1-20180412.0025.1523510700 results/yourthing/12/NSLookup/output.json
# python3 plot_data_trans.py results/yourthing/12/Classic/output.json results/yourthing/12/Classic



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
            python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/${flow_cate}/output.json
            # python3 plot_data_trans.py ${result_dir}/${dd}/${flow_cate}/output.json ${result_dir}/${dd}/${flow_cate}
        done

        # mkdir -p ${result_dir}/${dd}/Classic 
        # python3 regular_trace_extract2.py Classic /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/Classic/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/Classic/output.json ${result_dir}/${dd}/Classic

        # mkdir -p ${result_dir}/${dd}/PortLess 
        # python3 regular_trace_extract2.py PortLess /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/Classic/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/PortLess/output.json ${result_dir}/${dd}/PortLess

        # mkdir -p ${result_dir}/${dd}/SubnetLess8 
        # python3 regular_trace_extract2.py SubnetLess8 /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/Classic/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/SubnetLess8/output.json ${result_dir}/${dd}/SubnetLess8

        # mkdir -p ${result_dir}/${dd}/SubnetLess16 
        # python3 regular_trace_extract2.py SubnetLess16 /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/Classic/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/SubnetLess16/output.json ${result_dir}/${dd}/SubnetLess16

        # mkdir -p ${result_dir}/${dd}/NSLookup 
        # python3 regular_trace_extract2.py NSLookup /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/Classic/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/NSLookup/output.json ${result_dir}/${dd}/NSLookup
    done
done


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
            python3 regular_trace_extract2.py ${flow_cate} /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/${flow_cate}/output.json
            # python3 plot_data_trans.py ${result_dir}/${dd}/${flow_cate}/output.json ${result_dir}/${dd}/${flow_cate}
        done

        # mkdir -p ${result_dir}/${dd}/Classic 
        # python3 regular_trace_extract2.py Classic /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/Classic/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/Classic/output.json ${result_dir}/${dd}/Classic

        # mkdir -p ${result_dir}/${dd}/PortLess 
        # python3 regular_trace_extract2.py PortLess /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/PortLess/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/PortLess/output.json ${result_dir}/${dd}/PortLess

        # mkdir -p ${result_dir}/${dd}/SubnetLess8 
        # python3 regular_trace_extract2.py SubnetLess8 /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/SubnetLess8/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/SubnetLess8/output.json ${result_dir}/${dd}/SubnetLess8

        # mkdir -p ${result_dir}/${dd}/SubnetLess16 
        # python3 regular_trace_extract2.py SubnetLess16 /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/SubnetLess16/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/SubnetLess16/output.json ${result_dir}/${dd}/SubnetLess16

        # mkdir -p ${result_dir}/${dd}/NSLookup 
        # python3 regular_trace_extract2.py NSLookup /home/robin/datasets/moniotr/devices.json ${dataset_dir}/${dd} ${result_dir}/${dd}/NSLookup/output.json
        # python3 plot_data_trans.py ${result_dir}/${dd}/NSLookup/output.json ${result_dir}/${dd}/NSLookup
    done
done


cd ${curr_dir}