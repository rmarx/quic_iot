<template>

    <div>

        <select v-model="selectedDevice" @change="onDeviceSelected($event)">
            <option v-for="device in devices" :key="device.name" :value="device">
                {{ device.name }}
            </option>
        </select>

        Selected: {{ selectedDevice === null ? "none" : selectedDevice.name }}

        <div v-for="(trace,index) in traces" :key="index">

            <BurstGraphContainer :id="index" :trace="trace" :onShowModal="onShowModal" style="width: 700px; height: 700px; float: left;" />

        </div>

        <generic-modal v-model="showModal" :formatJSON="true" @confirm="confirm" @cancel="cancel">
            <template v-slot:title>{{modalTitle}}</template>
            <p>
            {{modalContent}}
            </p>
        </generic-modal>
    </div>

</template>

<script lang="ts">

    import { Options, Vue } from 'vue-class-component'
    import BurstGraphContainer from '@/components/burstgraph/BurstGraphContainer.vue' // @ is an alias to /src
    import GenericModal from "@/components/modal/GenericModal.vue"
    import NDJSONParser from '@/data/utils/NDJSONParser'

    @Options({
        components: {
            BurstGraphContainer,
            GenericModal
        }
    })
    export default class BurstGraph extends Vue {

        devices:Array<any> = new Array<any>();
        traces:Array<any> = new Array<any>();

        selectedDevice:any = null;

        showModal:boolean = false;
        modalTitle:string = "";
        modalContent:string = "";

        public created() {

            this.devices.push( { name: "moniotr - uk - echoplus", path: "moniotr/echoplus.json", data: null });
            this.devices.push( { name: "moniotr - uk - smarter-coffee-mach", path: "moniotr/smarter-coffee-mach.json", data: null });
            this.devices.push( { name: "moniotr - uk - t-philips-hub", path: "moniotr/t-philips-hub.json", data: null });

            
            this.devices.push( { name: "yourthings - 12 - AmazonEchoGen1", path: "yourthings/AmazonEchoGen1.json", data: null });
            this.devices.push( { name: "yourthings - 12 - AmazonFireTV", path: "yourthings/AmazonFireTV.json", data: null });
            this.devices.push( { name: "yourthings - 12 - BoseSoundTouch10", path: "yourthings/BoseSoundTouch10.json", data: null });
            this.devices.push( { name: "yourthings - 12 - ChineseWebcam", path: "yourthings/ChineseWebcam.json", data: null });
            this.devices.push( { name: "yourthings - 12 - GoogleHome", path: "yourthings/GoogleHome.json", data: null });
            this.devices.push( { name: "yourthings - 12 - NestCamera", path: "yourthings/NestCamera.json", data: null });
            this.devices.push( { name: "yourthings - 12 - Sonos", path: "yourthings/Sonos.json", data: null });
            this.devices.push( { name: "yourthings - 12 - AugustDoorbellCam", path: "yourthings/AugustDoorbellCam.json", data: null });

            // fetch('test.json')
            //     .then(response => response.body)
            //     .then(stream => { return NDJSONParser.parse(stream!); })
            //     .then(data => { console.log("data loaded", data); this.data = data; } );
        }

        public mounted() {
            this.selectedDevice = this.devices[0];
            this.onDeviceSelected({});

            console.log("SHOWING");
            // this.$vfm.show("mymodalexample"); 
            this.modalTitle = "Testing the title";
            this.modalContent = "Testing the content";
            this.showModal = true;
            console.error("Shown modals", this.$vfm.openedModals);
            console.log("DONE SHOWING");
        }

        protected confirm() { this.showModal = false; }
        protected cancel() { this.showModal = false; }

        protected onShowModal(title: string, contents: string): void {
            this.modalTitle = title;
            this.modalContent = contents;
            this.showModal = true;
        }

        protected onDeviceSelected(evt:any):void {
            // console.log("Event was selected", evt, this.selectedDevice);

            if ( this.selectedDevice.data === null ) {                
                fetch( this.selectedDevice.path )
                    .then(response => response.body)
                    .then(stream => { return NDJSONParser.parse(stream!); })
                    .then(data => { console.log("Device traces loaded", data); this.selectedDevice.data = data; this.traces = data/*.slice(0,50)*/; } );
            }
            else {
                this.traces = this.selectedDevice.data/*.slice(0,50)*/;
            }
        }
    }

</script>
