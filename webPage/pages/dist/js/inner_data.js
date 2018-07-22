/**
 * Created by lenovo on 2018/7/21.
 */

var dom = document.getElementById("e_chart_1");
var myChart = echarts.init(dom);
var option = null;
myChart.showLoading();
$.getJSON('/report/connection.json', function (data) {
// $.getJSON('testFiles/connection.json', function (data) {
    myChart.hideLoading();

    var categories = [
        {
            "name": "主机",
            "symbol": "circle",
            "itemStyle": {
                "color": "#76c880"
            }
        },{
            "name": "服务器",
            "symbol": "rect",
            "itemStyle": {
                "color": "#f73414"
            }
        }
    ]
    option = {
        tooltip: {},
        legend: [{
            // selectedMode: 'single',
            data: categories.map(function (a) {
                return a.name;
            })
        }],
        edgeLength: [20, 100],
        animationDuration: 1500,
        animationEasingUpdate: 'quinticInOut',
        series : [
            {
                name: 'connection',
                type: 'graph',
                layout: 'force',
                data: data.nodes,
                links: data.links,
                categories: categories,
                roam: true,
                focusNodeAdjacency: true,
                itemStyle: {
                    normal: {
                        borderColor: '#fff',
                        borderWidth: 1,
                        shadowBlur: 10,
                        shadowColor: 'rgba(0, 0, 0, 0.3)'
                    }
                },
                label: {
                    position: 'right',
                    formatter: '{b}'
                },
                emphasis: {
                    lineStyle: {
                        width: 10
                    }
                },
                force: {
                repulsion: 200
                }
            }
        ]
    };

    myChart.setOption(option);
});
if (option && typeof option === "object") {
    myChart.setOption(option, true);
}