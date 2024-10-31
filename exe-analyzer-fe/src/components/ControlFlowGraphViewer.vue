<template>
    <div>
        <div>
            <h1>{{ AppName }}({{ CFGInfo }})</h1>
        </div>
        <div class="button-container">
            <button @click="refreshCFGHandle">refresh cfg</button>
        </div>
        <div class="button-container">
            <input type="text" v-model="searchQuery" placeholder="Search Text" />
            <button @click="searchNodes">search</button>
            <button v-if="highlightElementsArray.length > 0" @click="searchNextNodes">searchNext</button>
        </div>
        <div class="container">
            <div ref="svgContainer" class="svg-container"></div>
            <HexViewer :dataMap="hexDataMap" :RIP="select_show_address" class="hex-viewer-container" />
        </div>
    </div>
</template>

<script>
import * as d3 from "d3";
import axios from 'axios';
import { API_BASE_URL } from '@/config'; // Adjust this path based on your file structure
import HexViewer from '@/components/HexViewer.vue';

export default {
    name: "ControlFlowGraphViewer",
    components: {
        HexViewer
    },
    data() {
        return {
            svgUrl: `${API_BASE_URL}/static/control_flow_graph.svg`, // SVG文件的后端URL
            user_start_address: 0,
            user_size: 0,
            select_show_address: "",
            hexDataMap: {},
            svg_node: null,
            g_node: null,
            AppName: "Loading...",
            CFGInfo: "",
            searchQuery: "",
            highlightElementsArray: [],
            currentFindIdx: 0,
        };
    },
    mounted() {
        this.loadSvg();
        this.fetchUserSection(); // fetch user code section
    },
    methods: {
        fetchUserSection() {
            let that = this;
            axios.get(`${API_BASE_URL}/user_section`)
                .then(response => {
                    const userSection = response.data;
                    that.user_start_address = BigInt(`${userSection['UserCodeStartAddress']}`);
                    that.user_size = BigInt(`${userSection['UserCodeStartSize']}`);
                    that.AppName = userSection['app'];
                    that.CFGInfo = userSection['info'];
                })
                .catch(error => {
                    console.error('Error fetching user section:', error);
                });
        },
        isUserSection(address) {
            return address >= this.user_start_address && address < (this.user_start_address + this.user_size);
        },
        fetchEmulateInfo(log_address) {
            return fetch(`${API_BASE_URL}/emulate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ "log_address": log_address })
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    return data; // 返回数据
                })
                .catch(error => {
                    // console.error('Error:', error);
                    alert(log_address + ": not found...");
                    throw error; // 抛出错误以便调用者处理
                });
        },
        refreshCFGHandle() {
            this.loadSvg();
        },

        searchNodes() {
            this.highlightElements();
        },
        searchNextNodes() {
            this.moveToTargetElment(this.highlightElementsArray[this.currentFindIdx++]);
        },
        moveToTargetElment(matchedElement) {
            if (!matchedElement) {
                alert("No Next...");
                return;
            }
            // 备份原始颜色
            const originalFill = matchedElement.getAttribute('fill') || 'black'; // 默认颜色为黑色
            console.log(originalFill);
            matchedElement.setAttribute('fill', 'green');
            const bbox = matchedElement.getBBox();
            const Widthmargin = 0; // 添加一些边距
            const Heightmargin = 0; // 添加一些边距
            const gBox = this.g_node.node().getBBox();
            const viewBoxX = bbox.x - this.$refs.svgContainer.clientWidth / 2;
            const viewBoxY = bbox.y - this.$refs.svgContainer.clientHeight / 2;
            const viewBoxWidth = gBox.width * 1.2 + Widthmargin;
            const viewBoxHeight = gBox.height * 1.2 + Heightmargin;
            // 设置SVG的viewBox属性
            this.svg_node.attr('viewBox', `${viewBoxX} ${viewBoxY} ${viewBoxWidth} ${viewBoxHeight}`);
            // 设置闪烁效果
            let isOriginalColor = false;
            const blinkInterval = 200; // 闪烁间隔（毫秒）
            const blinkDuration = 1000; // 总闪烁时间（毫秒）
            const intervalId = setInterval(() => {
                if (isOriginalColor) {
                    matchedElement.setAttribute('fill', 'green');
                } else {
                    matchedElement.setAttribute('fill', originalFill);
                }
                isOriginalColor = !isOriginalColor;
            }, blinkInterval);

            // 停止闪烁并恢复原始颜色
            setTimeout(() => {
                clearInterval(intervalId);
                matchedElement.setAttribute('fill', originalFill);
            }, blinkDuration);
        },
        highlightElements() {
            if (!this.svg_node) return;
            const query = this.searchQuery.toLowerCase();
            let found = false;
            const svgElement = this.svg_node.node(); // 获取原生的SVG DOM节点
            // 遍历所有的文本元素
            const textElements = svgElement.querySelectorAll('text');
            this.highlightElementsArray = [];
            this.currentFindIdx = 0;
            textElements.forEach((element) => {
                const text = element.textContent.toLowerCase();
                if (text.includes(query)) {
                    this.highlightElementsArray.push(element);
                }
            });
            // 如果找到匹配的元素，进行缩放和移动
            if (this.highlightElementsArray.length > 0) {
                this.searchNextNodes();
            }
        },
        loadSvg() {
            const svgContainer = this.$refs.svgContainer;
            // 使用D3加载SVG文件
            d3.xml(this.svgUrl).then((xml) => {
                const importedNode = document.importNode(xml.documentElement, true);
                // 清空容器，防止重复加载
                svgContainer.innerHTML = "";
                // 将SVG附加到容器
                svgContainer.appendChild(importedNode);
                // 选择SVG元素
                const svg = d3.select(svgContainer).select("svg");
                this.svg_node = svg;
                // 创建一个g元素来包裹所有内容
                let g = svg.append("g");
                this.g_node = g;
                Array.from(importedNode.childNodes).forEach((topchildNode) => {
                    Array.from(topchildNode.childNodes).forEach((childNode) => {
                        // g.node is doc
                        g.node().appendChild(childNode);
                    });
                });
                // Calculate the bounding box of the 'g' element
                const bbox = g.node().getBBox();
                // Set the viewBox of the SVG to focus on the 'g' element
                svg.attr("viewBox", `${bbox.x} ${bbox.y} ${bbox.width * 2} ${bbox.height * 2}`);
                // 其实只有这个有用
                Array.from(importedNode.childNodes[1].childNodes).forEach((childNode) => {
                    // console.log(childNode);
                    // g.node().appendChild(childNode);
                });
                const zoom = d3
                    .zoom()
                    .scaleExtent([0.1, 20]) // 允许的缩放范围
                    .on("zoom", (event) => {
                        g.attr("transform", event.transform);
                    });
                svg.call(zoom);
                svg.on("dblclick.zoom", null);
                this.hexDataMap = {}; // 清空
                let that = this;
                // 为每个节点注册点击事件
                g.selectAll("g").on("dblclick", function (event, d) {
                    // 修改为监听鼠标抬起事件
                    const node_address = this.baseURI.substring(this.baseURI.indexOf('-') + 1);
                    const type = this.baseURI.substring(this.baseURI.lastIndexOf('/') + 1, this.baseURI.indexOf('-'));

                    event.stopPropagation();
                    if (!that.isUserSection(BigInt(`${node_address}`))) {
                        console.log("is system dll section.... not important!");
                        return;
                    }
                    if (type != 'insn') {
                        console.log("pls db click accurate address not block!");
                        return;
                    }
                    const clickedNode = d3.select(this);
                    const bbox = this.getBBox(); // 获取点击节点的边界框

                    that.fetchEmulateInfo(node_address)
                        .then(data => {
                            const emul_info = data;
                            that.hexDataMap = data['mem_map'];
                            that.select_show_address = node_address;
                            const tableData = emul_info["reg"];
                            // Calculate the new position for the table (adjust as necessary)
                            const tableWidth = 400;
                            const widthOffset = 150;
                            let newX = bbox.x - tableWidth - widthOffset; // New table location to the right
                            let newY = bbox.y + 50; // New table location upwards
                            // Create a group for the new table
                            const newTable = g
                                .append("g")
                                .attr("transform", `translate(${newX},${newY})`);
                            // Append HTML table to the SVG
                            const dataArray = Object.entries(tableData);
                            const table = newTable.append("foreignObject")
                                .attr("width", tableWidth)  // Adjust width as needed
                                .attr("height", dataArray.length * 30)  // Adjust height based on number of rows
                                .append("xhtml:table")
                                .style("font-family", "Arial, sans-serif")
                                .style("border-collapse", "collapse")
                                .style("width", "100%");
                            // Append a header row
                            const headerRow = table.append("tr");
                            headerRow.append("th").text("Register").style("border", "1px solid black").style("padding", "5px");
                            headerRow.append("th").text("Value").style("border", "1px solid black").style("padding", "5px");
                            // Append rows for each item in the data
                            dataArray.forEach(([key, value]) => {
                                const row = table.append("tr");
                                row.append("td").text(key).style("border", "1px solid black").style("padding", "5px");
                                row.append("td").text(value).style("border", "1px solid black").style("padding", "5px");
                            });
                            // Optional: Create a connecting line (if necessary)
                            g.append("line")
                                .attr("x1", bbox.x)
                                .attr("y1", bbox.y)
                                .attr("x2", newX + tableWidth)
                                .attr("y2", newY + dataArray.length * 15) // Adjust if necessary
                                .attr("stroke", "blue")
                                .attr("stroke-width", 2);
                        })
                        .catch(error => {
                            console.error('Error fetching emulate info:', error);
                        });

                });
            });
        },
    },
};
</script>

<style>
.button-container {
    display: flex;
    justify-content: flex-start;
    /* Aligns the button to the left */
    margin-bottom: 10px;
    /* Adds some space below the button */
}

.svg-container {
    width: 78%;
    height: 83vh;
    overflow: hidden;
    border: 1px solid #ccc;
    cursor: grab;
    /* 设置鼠标指针样式 */
}

.svg-container:active {
    cursor: grabbing;
    /* 拖动时的鼠标指针样式 */
}

.container {
    height: 80%;
    display: flex;
    /* 使用flex布局 */
    flex-direction: row;
    /* 默认值是row，这里确保是水平排列 */
    justify-content: space-between;
    /* 根据需要调整间距 */
    align-items: flex-start;
    /* 根据需要调整垂直对齐方式 */
}

.hex-viewer-container {
    width: 22%;
    height: 83vh;
}
</style>