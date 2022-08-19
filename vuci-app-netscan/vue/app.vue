<template>
  <div class="netscan">
    <div class="hosts-border">
      <div>
        <img src="/icons/globe.png" class="globe"/>
      </div>
      <div class="wan-connection">
        <img v-if="wanIsUp" src="/icons/v_line.png" style="width: 50px; height: 100%"/>
        <img v-else src="/icons/error.png"/>
      </div>
      <img src="/icons/new_router.png" class="router"/>
      <div style="font-size: 12px">
        <strong>IP: </strong>{{routerLanAddress}}
      </div>
      <div v-if="!loading && hosts" class="hosts">
        <div v-for="host,index in hosts" :key="index" class="host">
          <img src="/icons/device.png" class="host-device"/>
          <div class="host-ip">
            <strong>IP: </strong>{{host.ipNumber}}
          </div>
        </div>
      </div>
      <div v-if="!loading && !hosts" class="no-hosts">NO HOSTS</div>
      <img v-if="loading" src="/icons/loading.gif" class="loading-hosts"/>
    </div>
    <div class="input-block">
      <div class="subnet-label">IP address</div>
      <div>
        <a-input :class="!ipError ? 'subnet-input' : 'subnet-input error'" v-model="ip" placeholder="192.168.10.0" @change="validateIP"></a-input>
        <div class="scan-input-error">{{ipError}}</div>
      </div>
      <div class="subnet-label">Netmask size</div>
      <div>
        <a-input :class="!maskError ? 'subnet-input' : 'subnet-input error'" v-model="mask" placeholder="24" type="number" min="0" max="32" @change="validateMask"></a-input>
        <div class="scan-input-error">{{maskError}}</div>
      </div>
    </div>
    <div class="scan-actions">
      <a-button @click="startScan" :disabled="!subnet">Start</a-button>
      <a-button @click="stopScan">Stop</a-button>
    </div>
  </div>
</template>
<script>
import validator from '@/plugins/vuci-validator'
export default {
  data () {
    return {
      ip: '',
      mask: '',
      hosts: '',
      loading: false,
      routerLanAddress: '',
      ipError: '',
      maskError: '',
      wanIsUp: false
    }
  },
  timers: {
    getScanResults: { time: 1000, immediate: false, repeat: true }
  },
  computed: {
    subnet () {
      let subnet = ''
      if (!this.ipError && !this.maskError && this.ip && this.mask) {
        subnet = this.ip + '/' + this.mask
      }
      return subnet
    }
  },
  methods: {
    startScan () {
      this.hosts = ''
      this.loading = true
      this.$rpc.call('netscan', 'start_scan', { subnet: this.subnet }).then(() => {
        this.$timer.start('getScanResults')
      })
    },
    getScanResults () {
      this.$rpc.call('netscan', 'get_results').then(response => {
        if (response.ok === true) {
          if (response.type === 'hosts') {
            this.hosts = response.data.hosts
            this.$timer.stop('getScanResults')
          } else if (response.type === 'error') {
            this.$timer.stop('getScanResults')
            this.$message.error(response.data[0].split(':').pop())
          }
          this.loading = false
        } else if (response.ok === false) {
          this.loading = true
        }
      })
    },
    validateIP () {
      console.log()
      if (!validator.ip4addr(this.ip) && this.ip !== '') {
        this.ipError = 'Must be an IP address'
      } else {
        this.ipError = ''
      }
    },
    validateMask () {
      if ((this.mask < 16 || this.mask > 32 || typeof parseInt(this.mask) !== 'number') && this.mask !== '') {
        this.maskError = 'Number is out of range (16-32)'
      } else {
        this.maskError = ''
      }
    },
    stopScan () {
      this.loading = false
      this.$rpc.call('netscan', 'stop_scan').then(() => {
        this.$timer.stop('getScanResults')
      })
    }
  },
  mounted () {
    this.$network.load().then(() => {
      if (this.$network.getInterface('wan')) {
        this.wanIsUp = true
      }
      this.routerLanAddress = this.$network.getInterface('lan').status['ipv4-address'][0].address
    })
  }
}
</script>
<style>
  .hosts-border {
    border: 1px solid #e1e1e1;
    border-radius: 3px;
    padding: 10px 15px;
    width: 100%;
    min-height: 350px;
    margin: 10px 0;
    text-align: center;
  }
  .globe {
    width: 90px;
  }
  .router {
    filter: brightness(110%);
  }
  .loading-hosts {
    width: 100px;
    margin: 50px auto;
    filter: brightness(130%) contrast(110%);
  }
  .hosts {
    position: relative;
    text-align: center;
    margin: 20px;
  }
  .host {
    margin: 5px;
    display: inline-block;
    padding: 10px;
  }
  .host-device {
    width: 80px;
    filter: contrast(120%) saturate(2);
  }
  .host-ip {
    font-size: 12px;
  }
  .no-hosts {
    vertical-align: middle;
    line-height: 200px;
  }
  .input-block {
    display: flex;
    white-space: pre;
    justify-content: center;
    margin: 20px;
  }
  .subnet-label {
    line-height: 2;
    margin-right: 5px;
    margin-left: 10px;
  }
  .subnet-input {
    padding-right: 10px;
    width: 200px;
  }
  .scan-input-error {
    color: red;
  }
  .scan-actions {
    text-align: center;
    margin: 10px;
  }
  .error:focus {
    box-shadow: 0 0 3px red !important;
  }
  .error:focus {
    border: 1px solid red !important;
  }
  .wan-connection {
    height: 70px;
    display: block;
    width: 50px;
    margin: 10px auto 0 auto;
  }
</style>
