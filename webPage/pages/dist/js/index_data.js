/**
 * Created by lenovo on 2018/7/21.
 */
$(function() {
	"use strict";
	$.getJSON ("/report/infected_computer.json", function (data) {
	// $.getJSON ("testFiles/infected_computer.json", function (data) {
        Morris.Line({
            element: 'infected_computer',
            data: data,
            xkey: 'time',
            ykeys: ['infected'],
            labels: ['被感染主机'],
            pointSize: 2,
            fillOpacity: 0,
            lineWidth:2,
            pointStrokeColors:['#f73414'],
            behaveLikeLine: true,
            grid: false,
            hideHover: 'auto',
            lineColors: ['#f73414'],
            resize: true,
            gridTextColor:'#878787',
            gridTextFamily:"Montserrat"
        });
        // LineChartData(
        //     'infected_computer',
        //     data,
        //     'time',
        //     ['infected'],
        //     ['被感染主机'],
        //     ['#f73414'],
        //     ['#f73414']
        // );
    });
	$.getJSON ("/report/active_software.json", function (data) {
	// $.getJSON ("testFiles/active_software.json", function (data) {
        Morris.Line({
            element: 'active_software',
            data: data,
            xkey: 'time',
            ykeys: ['benign', 'malicious'],
            labels: ['良性软件', '恶意软件（×50）'],
            pointSize: 2,
            fillOpacity: 0,
            lineWidth:2,
            pointStrokeColors:['#76c880', '#f73414'],
            behaveLikeLine: true,
            grid: false,
            hideHover: 'auto',
            lineColors: ['#76c880', '#f73414'],
            resize: true,
            gridTextColor:'#878787',
            gridTextFamily:"Montserrat",
            smooth: false
        });
        // LineChartData(
        //     'active_software',
        //     data,
        //     'time',
        //     ['benign', 'malicious'],
        //     ['良性软件', '恶意软件'],
        //     ['#76c880', '#f73414'],
        //     ['#76c880', '#f73414']
        // );
    });
	$.getJSON ("/mad/loss.json", function (data) {
	// $.getJSON ("testFiles/loss.json", function (data) {
	    data.forEach(function(node){node.loss=1-node.loss;});
	    Morris.Line({
            element: 'loss',
            data: data,
            xkey: 'time',
            ykeys: ['loss'],
            labels: ['loss'],
            pointSize: 2,
            fillOpacity: 0,
            lineWidth:2,
            pointStrokeColors:['#76c880'],
            behaveLikeLine: true,
            grid: false,
            hideHover: 'auto',
            lineColors: ['#76c880'],
            resize: true,
            gridTextColor:'#878787',
            gridTextFamily:"Montserrat",
            smooth: false
        });
        // LineChartData(
        //     'loss',
        //     data,
        //     'time',
        //     ['loss'],
        //     ['loss'],
        //     ['#76c880'],
        //     ['#76c880']
        // );
    });

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
            edgeLength: [30, 100],
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

});

function LineChartData(element, data, x, y, labels, pointColor, lineColor) {
	"use strict";
    Morris.Line({
        element: element,
        data: data,
        xkey: x,
        ykeys: y,
        labels: labels,
        pointSize: 2,
        fillOpacity: 0,
        lineWidth:2,
        pointStrokeColors:pointColor,
        behaveLikeLine: true,
        grid: false,
        hideHover: 'auto',
        lineColors: lineColor,
        resize: true,
        gridTextColor:'#878787',
        gridTextFamily:"Montserrat"
    });
}