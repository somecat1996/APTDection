/**
 * Created by lenovo on 2018/7/20.
 */
var count = 1;
var Data = [];
$.getJSON ("/report/loss.json", function (data) {
// $.getJSON ("testFiles/loss.json", function (data) {
    count = data.length;
    $.each(data, function (i, item) {
        Data.push({
            period: item.time.replace('T', ' '),
            loss: item.loss
        });
        count--;
    });
});
setTimeout(function() {
	"use strict";
    Morris.Area({
        element: 'morris_area_chart',
        data: Data,
        xkey: 'period',
        ykeys: ['loss'],
        labels: ['误报数：正确数'],
        pointSize: 0,
        lineWidth:0,
        fillOpacity: 1,
        pointStrokeColors:['#76c880'],
        behaveLikeLine: true,
        grid: false,
        hideHover: 'auto',
        lineColors: ['#76c880'],
        resize: true,
        redraw: true,
        smooth: true,
        gridTextColor:'#878787',
        gridTextFamily:"Montserrat",
    });
}, 2*1000);
// $(document).ready(function() {
// 	"use strict";
// 	console.log(data);
//     Morris.Area({
//         element: 'morris_area_chart',
//         data: data,
//         xkey: 'period',
//         ykeys: ['loss'],
//         labels: ['误报数：正确数'],
//         pointSize: 0,
//         lineWidth:0,
//         fillOpacity: 1,
//         pointStrokeColors:['#76c880'],
//         behaveLikeLine: true,
//         grid: false,
//         hideHover: 'auto',
//         lineColors: ['#76c880'],
//         resize: true,
//         redraw: true,
//         smooth: true,
//         gridTextColor:'#878787',
//         gridTextFamily:"Montserrat",
//     });
// });