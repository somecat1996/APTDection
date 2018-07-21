/**
 * Created by lenovo on 2018/7/21.
 */
$(function() {
	"use strict";
	$.getJSON ("testFiles/infected_computer.json", function (data) {
        LineChartData(
            'infected_computer',
            data,
            'time',
            ['infected'],
            ['被感染主机'],
            ['#f73414'],
            ['#f73414']
        );
    });
	$.getJSON ("testFiles/active_software.json", function (data) {
        LineChartData(
            'active_software',
            data,
            'time',
            ['benign', 'malicious'],
            ['良性软件', '恶意软件'],
            ['#76c880', '#f73414'],
            ['#76c880', '#f73414']
        );
    });
	$.getJSON ("testFiles/loss.json", function (data) {
        LineChartData(
            'loss',
            data,
            'time',
            ['loss'],
            ['loss'],
            ['#76c880'],
            ['#76c880']
        );
    });
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