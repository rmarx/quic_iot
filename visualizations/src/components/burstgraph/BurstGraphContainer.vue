<template>
    <div>
        <!-- <p>{{ trace.trace }}</p> -->
        <div :id="traceID" style="width: 100%; height: 100%; border: 1px solid black; background-color: #f1f1f1;" />
    </div>
</template>


<script lang="ts">
    import { Options, Vue } from "vue-class-component";
    import { PropType } from "vue";
    import { BurstGraphRendererD3 } from "./renderers/BurstGraphRendererD3";

    @Options({
        props: {
            trace: Object,
            id: Number,

            onShowModal: { 
                type: Function as PropType<(title: string, contents:string ) => void>
            }
        },
    })
    export default class BurstGraphContainer extends Vue {
        trace!: any;
        id!: number;

        onShowModal!: (title: string, contents:string ) => void;

        renderer!: BurstGraphRendererD3;

        public get traceID() {
            return "burstgraphcontainer_" + this.id;
        }

        public created() {
            console.log("BurstGraphRenderer created!");

            this.renderer = new BurstGraphRendererD3(this.triggerShowModal);
        }

        // this.updated isn't called the first time around
        public mounted() {
            this.rerender();
        }

        public updated() {
            this.rerender();
        }

        protected rerender() {
            // console.log("UPDATED: Rendering trace", this.trace.trace);
            this.renderer.render(
                this.traceID,
                this.trace
            );
        }

        protected triggerShowModal(title: string, contents: string ){
            if ( this.onShowModal !== undefined ) {
                console.log("trying to show modal from D3 click:", title, contents);
                this.onShowModal(title, contents);
            }
            else {
                console.error("BurstGraphContainer:triggerShowModal: no modal callback defined!");
            }
        }
    }
</script>

