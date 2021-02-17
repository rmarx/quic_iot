import { BootstrapVue } from 'bootstrap-vue'
import VueFinalModal from 'vue-final-modal'

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

import 'bootstrap/dist/css/bootstrap.css'
// import 'bootstrap-vue/dist/bootstrap-vue.css'
// bootstrap-vue wasn't really compatible with Vue 3 yet (gave error: Cannot read property 'prototype' of undefined)
// so had to manually change the src/utils/config.js according to this: https://github.com/bootstrap-vue/bootstrap-vue/issues/5196#issuecomment-697575376
// which also didn't work, so can't use that for now. Thanks obama

let app = createApp(App);
// app.use( BootstrapVue );
// app.use( VueFinalModal() );
app.use( VueFinalModal() ).use(router).mount('#app');  
