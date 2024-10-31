<template>
  <div ref="hexViewer" class="hex-viewer">
    <div class="controls">
      <select v-model="selectedAddress" @change="resetPagination">
        <option v-for="(hexData, address) in dataMap" :key="address" :value="address">
          {{ address }}
        </option>
      </select>
      <input type="text" v-model="inputAddress" placeholder="Enter address" />
      <button @click="goToAddress">Go</button>
    </div>
    <div v-if="RIP" class="rip-display">
      <strong>RIP:</strong> {{ RIP }}
    </div>

    <div v-if="selectedAddress" class="hex-section">
      <div class="address-column">
        <div v-for="(line, index) in paginatedLines(dataMap[selectedAddress])" :key="'address-' + index" class="address">
          {{ formatAddress(selectedAddress, currentLine + index) }}
        </div>
      </div>
      <div class="hex-column">
        <div v-for="(line, index) in paginatedLines(dataMap[selectedAddress])" :key="'hex-' + index" class="hex-line" ref="lineElement">
          <span v-for="(byte, byteIndex) in line" :key="'hex-byte-' + index + '-' + byteIndex" class="byte">
            {{ byte }}
          </span>
        </div>
      </div>
      <div class="ascii-column">
        <div v-for="(line, index) in paginatedLines(dataMap[selectedAddress])" :key="'ascii-' + index" class="ascii-line">
          <span v-for="(byte, byteIndex) in line" :key="'ascii-byte-' + index + '-' + byteIndex" class="ascii">
            {{ byteToAscii(byte) }}
          </span>
        </div>
      </div>
    </div>

    <div class="navigation-buttons" v-if="selectedAddress">
      <button @click="prevPage" :disabled="currentLine === 0">Previous</button>
      <button @click="nextPage" :disabled="!hasMoreData">Next</button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'HexViewer',
  props: {
    dataMap: {
      type: Object,
      required: true
    },
    RIP: {
      type: String,
      default: null
    }
  },
  data() {
    return {
      selectedAddress: Object.keys(this.dataMap)[0] || null,
      inputAddress: '',
      currentLine: 0,
      linesPerPage: 50 // Default value, will be recalculated
    };
  },
  computed: {
    hasMoreData() {
      if (!this.selectedAddress) return false;
      const totalLines = this.getLines(this.dataMap[this.selectedAddress]).length;
      return this.currentLine + this.linesPerPage < totalLines;
    }
  },
  mounted() {
    this.calculateLinesPerPage();
    // window.addEventListener('resize', this.calculateLinesPerPage);
  },
  beforeDestroy() {
    // window.removeEventListener('resize', this.calculateLinesPerPage);
  },
  methods: {
    calculateLinesPerPage() {
      this.$nextTick(() => {
        const hexViewerHeight = this.$refs.hexViewer.offsetHeight;
        const lineElement = this.$refs.lineElement && this.$refs.lineElement[0];
        if (lineElement) {
          const lineHeight = lineElement.offsetHeight;
          this.linesPerPage = Math.floor(hexViewerHeight / lineHeight) - 20;
        }
      });
    },
    getBytes(hexString) {
      const bytes = [];
      for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(hexString.substr(i, 2));
      }
      return bytes;
    },
    getLines(hexString) {
      const bytes = this.getBytes(hexString['content']);
      const lines = [];
      for (let i = 0; i < bytes.length; i += 16) {
        lines.push(bytes.slice(i, i + 16));
      }
      return lines;
    },
    paginatedLines(hexString) {
      const lines = this.getLines(hexString);
      return lines.slice(this.currentLine, this.currentLine + this.linesPerPage);
    },
    formatAddress(address, index) {
      const baseAddress = parseInt(address, 16) + index * 16;
      return baseAddress.toString(16).padStart(8, '0').toUpperCase();
    },
    byteToAscii(byte) {
      const char = String.fromCharCode(parseInt(byte, 16));
      return char.replace(/[^\x20-\x7E]/g, '.');
    },
    nextPage() {
      if (this.hasMoreData) {
        this.currentLine += this.linesPerPage;
      }
    },
    prevPage() {
      if (this.currentLine > 0) {
        this.currentLine -= this.linesPerPage;
      }
    },
    resetPagination() {
      this.currentLine = 0;
    },
    goToAddress() {
      const addressInt = parseInt(this.inputAddress, 16);
      let found = false;
      for (const address in this.dataMap) {
        const startInt = parseInt(address, 16);
        const totalLines = this.getLines(this.dataMap[address]).length;
        const endInt = startInt + totalLines * 16;
        if (addressInt >= startInt && addressInt < endInt) {
          this.selectedAddress = address;
          this.currentLine = Math.floor((addressInt - startInt) / 16);
          found = true;
          break;
        }
      }
      if (!found) {
        alert(`Address ${this.inputAddress} not found in any range`);
      }
    }
  }
}
</script>

<style scoped>
.hex-viewer {
  display: flex;
  flex-direction: column;
  font-family: monospace;
  height: 100%; /* Make sure the component uses its container's full height */
  overflow: hidden; /* Prevent overflow issues */
}

.controls {
  display: flex;
  align-items: center;
  margin-bottom: 20px;
}

.controls select,
.controls input,
.controls button {
  margin-right: 10px;
}

.hex-section {
  display: flex;
  margin-bottom: 20px;
  overflow-y: auto; /* Enable scrolling if content overflows */
}

.address-column,
.hex-column,
.ascii-column {
  margin-right: 10px;
}

.address,
.hex-line,
.ascii-line {
  display: flex;
}

.byte {
  width: 24px;
  text-align: center;
}

.ascii {
  width: 14px;
  text-align: center;
}

.navigation-buttons {
  display: flex;
  justify-content: center;
  margin-top: 10px;
}

button {
  margin: 0 5px;
  padding: 5px 10px;
}

.rip-display {
  margin-top: 10px;
  font-weight: bold;
}
</style>
