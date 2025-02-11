// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

/*
 *
 * Ported from TCPLIB. Header file of smtp.c.
 */

/*
 * Copyright (c) 1991 University of Southern California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Southern California. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
*/

static struct entry itemsize[] =
{
    { 0.000000F, 0.000000F },
    { 25.000000F, 0.008000F },
    { 45.000000F, 0.009000F },
    { 60.000000F, 0.015000F },
    { 80.000000F, 0.016000F },
    { 95.000000F, 0.017000F },
    { 105.000000F, 0.018000F },
    { 115.000000F, 0.019000F },
    { 135.000000F, 0.020000F },
    { 140.000000F, 0.021000F },
    { 145.000000F, 0.022000F },
    { 150.000000F, 0.024000F },
    { 160.000000F, 0.025000F },
    { 170.000000F, 0.026000F },
    { 175.000000F, 0.027000F },
    { 180.000000F, 0.030000F },
    { 185.000000F, 0.032000F },
    { 190.000000F, 0.035000F },
    { 195.000000F, 0.038000F },
    { 200.000000F, 0.040000F },
    { 205.000000F, 0.042000F },
    { 210.000000F, 0.043000F },
    { 215.000000F, 0.044000F },
    { 220.000000F, 0.047000F },
    { 225.000000F, 0.049000F },
    { 230.000000F, 0.050000F },
    { 240.000000F, 0.051000F },
    { 245.000000F, 0.054000F },
    { 250.000000F, 0.056000F },
    { 255.000000F, 0.060000F },
    { 260.000000F, 0.061000F },
    { 265.000000F, 0.063000F },
    { 270.000000F, 0.066000F },
    { 275.000000F, 0.068000F },
    { 280.000000F, 0.073000F },
    { 285.000000F, 0.076000F },
    { 290.000000F, 0.080000F },
    { 295.000000F, 0.085000F },
    { 300.000000F, 0.094000F },
    { 305.000000F, 0.102000F },
    { 310.000000F, 0.111000F },
    { 315.000000F, 0.123000F },
    { 320.000000F, 0.138000F },
    { 325.000000F, 0.156000F },
    { 330.000000F, 0.181000F },
    { 335.000000F, 0.209000F },
    { 340.000000F, 0.241000F },
    { 345.000000F, 0.272000F },
    { 350.000000F, 0.302000F },
    { 355.000000F, 0.334000F },
    { 360.000000F, 0.362000F },
    { 365.000000F, 0.384000F },
    { 370.000000F, 0.404000F },
    { 375.000000F, 0.419000F },
    { 380.000000F, 0.432000F },
    { 385.000000F, 0.447000F },
    { 390.000000F, 0.455000F },
    { 395.000000F, 0.463000F },
    { 400.000000F, 0.468000F },
    { 405.000000F, 0.475000F },
    { 410.000000F, 0.478000F },
    { 415.000000F, 0.483000F },
    { 420.000000F, 0.487000F },
    { 425.000000F, 0.491000F },
    { 430.000000F, 0.495000F },
    { 435.000000F, 0.497000F },
    { 440.000000F, 0.501000F },
    { 445.000000F, 0.502000F },
    { 450.000000F, 0.504000F },
    { 455.000000F, 0.506000F },
    { 460.000000F, 0.507000F },
    { 465.000000F, 0.509000F },
    { 470.000000F, 0.512000F },
    { 475.000000F, 0.514000F },
    { 480.000000F, 0.516000F },
    { 485.000000F, 0.518000F },
    { 490.000000F, 0.520000F },
    { 495.000000F, 0.521000F },
    { 500.000000F, 0.523000F },
    { 510.000000F, 0.526000F },
    { 520.000000F, 0.529000F },
    { 530.000000F, 0.537000F },
    { 540.000000F, 0.540000F },
    { 550.000000F, 0.543000F },
    { 560.000000F, 0.546000F },
    { 570.000000F, 0.548000F },
    { 580.000000F, 0.552000F },
    { 590.000000F, 0.554000F },
    { 600.000000F, 0.563000F },
    { 610.000000F, 0.571000F },
    { 620.000000F, 0.574000F },
    { 630.000000F, 0.577000F },
    { 640.000000F, 0.580000F },
    { 650.000000F, 0.584000F },
    { 660.000000F, 0.586000F },
    { 670.000000F, 0.589000F },
    { 680.000000F, 0.591000F },
    { 690.000000F, 0.594000F },
    { 700.000000F, 0.597000F },
    { 710.000000F, 0.600000F },
    { 720.000000F, 0.603000F },
    { 730.000000F, 0.606000F },
    { 740.000000F, 0.611000F },
    { 750.000000F, 0.621000F },
    { 760.000000F, 0.626000F },
    { 770.000000F, 0.629000F },
    { 780.000000F, 0.636000F },
    { 790.000000F, 0.642000F },
    { 800.000000F, 0.645000F },
    { 810.000000F, 0.648000F },
    { 820.000000F, 0.655000F },
    { 830.000000F, 0.659000F },
    { 840.000000F, 0.662000F },
    { 850.000000F, 0.664000F },
    { 860.000000F, 0.672000F },
    { 870.000000F, 0.679000F },
    { 880.000000F, 0.682000F },
    { 890.000000F, 0.685000F },
    { 900.000000F, 0.688000F },
    { 910.000000F, 0.692000F },
    { 920.000000F, 0.695000F },
    { 930.000000F, 0.698000F },
    { 940.000000F, 0.700000F },
    { 950.000000F, 0.702000F },
    { 960.000000F, 0.707000F },
    { 970.000000F, 0.711000F },
    { 980.000000F, 0.713000F },
    { 990.000000F, 0.716000F },
    { 1000.000000F, 0.718000F },
    { 1010.000000F, 0.721000F },
    { 1020.000000F, 0.723000F },
    { 1030.000000F, 0.725000F },
    { 1040.000000F, 0.727000F },
    { 1050.000000F, 0.728000F },
    { 1060.000000F, 0.730000F },
    { 1070.000000F, 0.732000F },
    { 1080.000000F, 0.734000F },
    { 1090.000000F, 0.736000F },
    { 1100.000000F, 0.737000F },
    { 1110.000000F, 0.739000F },
    { 1120.000000F, 0.741000F },
    { 1130.000000F, 0.743000F },
    { 1140.000000F, 0.745000F },
    { 1150.000000F, 0.747000F },
    { 1160.000000F, 0.748000F },
    { 1170.000000F, 0.750000F },
    { 1180.000000F, 0.752000F },
    { 1190.000000F, 0.753000F },
    { 1200.000000F, 0.759000F },
    { 1210.000000F, 0.763000F },
    { 1220.000000F, 0.765000F },
    { 1230.000000F, 0.767000F },
    { 1240.000000F, 0.768000F },
    { 1250.000000F, 0.770000F },
    { 1260.000000F, 0.772000F },
    { 1270.000000F, 0.774000F },
    { 1280.000000F, 0.776000F },
    { 1290.000000F, 0.777000F },
    { 1300.000000F, 0.778000F },
    { 1310.000000F, 0.780000F },
    { 1320.000000F, 0.781000F },
    { 1330.000000F, 0.782000F },
    { 1340.000000F, 0.783000F },
    { 1350.000000F, 0.784000F },
    { 1360.000000F, 0.785000F },
    { 1370.000000F, 0.787000F },
    { 1380.000000F, 0.788000F },
    { 1390.000000F, 0.790000F },
    { 1400.000000F, 0.791000F },
    { 1410.000000F, 0.793000F },
    { 1420.000000F, 0.796000F },
    { 1430.000000F, 0.797000F },
    { 1440.000000F, 0.798000F },
    { 1450.000000F, 0.800000F },
    { 1460.000000F, 0.801000F },
    { 1470.000000F, 0.802000F },
    { 1480.000000F, 0.803000F },
    { 1490.000000F, 0.804000F },
    { 1500.000000F, 0.805000F },
    { 1510.000000F, 0.807000F },
    { 1520.000000F, 0.809000F },
    { 1530.000000F, 0.810000F },
    { 1540.000000F, 0.811000F },
    { 1550.000000F, 0.812000F },
    { 1560.000000F, 0.813000F },
    { 1570.000000F, 0.814000F },
    { 1580.000000F, 0.816000F },
    { 1590.000000F, 0.817000F },
    { 1600.000000F, 0.819000F },
    { 1610.000000F, 0.821000F },
    { 1620.000000F, 0.822000F },
    { 1630.000000F, 0.823000F },
    { 1650.000000F, 0.824000F },
    { 1660.000000F, 0.825000F },
    { 1670.000000F, 0.826000F },
    { 1680.000000F, 0.827000F },
    { 1690.000000F, 0.828000F },
    { 1700.000000F, 0.829000F },
    { 1710.000000F, 0.830000F },
    { 1730.000000F, 0.831000F },
    { 1740.000000F, 0.832000F },
    { 1760.000000F, 0.833000F },
    { 1780.000000F, 0.834000F },
    { 1800.000000F, 0.835000F },
    { 1810.000000F, 0.836000F },
    { 1820.000000F, 0.837000F },
    { 1830.000000F, 0.838000F },
    { 1850.000000F, 0.839000F },
    { 1860.000000F, 0.840000F },
    { 1870.000000F, 0.841000F },
    { 1890.000000F, 0.842000F },
    { 1900.000000F, 0.843000F },
    { 1910.000000F, 0.844000F },
    { 1930.000000F, 0.845000F },
    { 1950.000000F, 0.846000F },
    { 1960.000000F, 0.848000F },
    { 1970.000000F, 0.849000F },
    { 1980.000000F, 0.850000F },
    { 1990.000000F, 0.851000F },
    { 2000.000000F, 0.852000F },
    { 2010.000000F, 0.853000F },
    { 2030.000000F, 0.854000F },
    { 2040.000000F, 0.855000F },
    { 2070.000000F, 0.856000F },
    { 2090.000000F, 0.857000F },
    { 2110.000000F, 0.858000F },
    { 2120.000000F, 0.859000F },
    { 2130.000000F, 0.860000F },
    { 2150.000000F, 0.861000F },
    { 2170.000000F, 0.862000F },
    { 2190.000000F, 0.863000F },
    { 2210.000000F, 0.864000F },
    { 2240.000000F, 0.865000F },
    { 2280.000000F, 0.866000F },
    { 2300.000000F, 0.867000F },
    { 2330.000000F, 0.868000F },
    { 2360.000000F, 0.869000F },
    { 2390.000000F, 0.870000F },
    { 2400.000000F, 0.871000F },
    { 2420.000000F, 0.873000F },
    { 2440.000000F, 0.874000F },
    { 2450.000000F, 0.875000F },
    { 2460.000000F, 0.879000F },
    { 2470.000000F, 0.882000F },
    { 2480.000000F, 0.883000F },
    { 2500.000000F, 0.884000F },
    { 2510.000000F, 0.885000F },
    { 2520.000000F, 0.888000F },
    { 2530.000000F, 0.891000F },
    { 2540.000000F, 0.892000F },
    { 2560.000000F, 0.893000F },
    { 2570.000000F, 0.894000F },
    { 2590.000000F, 0.895000F },
    { 2620.000000F, 0.896000F },
    { 2640.000000F, 0.897000F },
    { 2660.000000F, 0.898000F },
    { 2670.000000F, 0.899000F },
    { 2680.000000F, 0.901000F },
    { 2700.000000F, 0.902000F },
    { 2730.000000F, 0.903000F },
    { 2750.000000F, 0.904000F },
    { 2770.000000F, 0.905000F },
    { 2790.000000F, 0.906000F },
    { 2810.000000F, 0.907000F },
    { 2840.000000F, 0.908000F },
    { 2850.000000F, 0.909000F },
    { 2870.000000F, 0.910000F },
    { 2900.000000F, 0.911000F },
    { 2930.000000F, 0.912000F },
    { 2940.000000F, 0.913000F },
    { 2970.000000F, 0.914000F },
    { 2990.000000F, 0.915000F },
    { 3000.000000F, 0.916000F },
    { 3010.000000F, 0.919000F },
    { 3020.000000F, 0.922000F },
    { 3040.000000F, 0.923000F },
    { 3070.000000F, 0.924000F },
    { 3100.000000F, 0.925000F },
    { 3160.000000F, 0.926000F },
    { 3210.000000F, 0.927000F },
    { 3250.000000F, 0.928000F },
    { 3280.000000F, 0.929000F },
    { 3340.000000F, 0.930000F },
    { 3430.000000F, 0.931000F },
    { 3480.000000F, 0.932000F },
    { 3500.000000F, 0.935000F },
    { 3520.000000F, 0.936000F },
    { 3550.000000F, 0.937000F },
    { 3580.000000F, 0.938000F },
    { 3620.000000F, 0.939000F },
    { 3630.000000F, 0.940000F },
    { 3640.000000F, 0.941000F },
    { 3690.000000F, 0.942000F },
    { 3770.000000F, 0.943000F },
    { 3840.000000F, 0.944000F },
    { 3860.000000F, 0.945000F },
    { 3950.000000F, 0.946000F },
    { 4020.000000F, 0.947000F },
    { 4050.000000F, 0.948000F },
    { 4120.000000F, 0.949000F },
    { 4290.000000F, 0.950000F },
    { 4320.000000F, 0.951000F },
    { 4410.000000F, 0.952000F },
    { 4540.000000F, 0.953000F },
    { 4550.000000F, 0.958000F },
    { 4560.000000F, 0.960000F },
    { 4580.000000F, 0.961000F },
    { 4610.000000F, 0.962000F },
    { 4670.000000F, 0.963000F },
    { 4940.000000F, 0.964000F },
    { 4990.000000F, 0.965000F },
    { 5000.000000F, 0.968000F },
    { 5500.000000F, 0.969000F },
    { 6000.000000F, 0.970000F },
    { 7500.000000F, 0.971000F },
    { 8000.000000F, 0.973000F },
    { 9500.000000F, 0.974000F },
    { 11000.000000F, 0.975000F },
    { 12500.000000F, 0.976000F },
    { 13000.000000F, 0.982000F },
    { 13500.000000F, 0.988000F },
    { 14000.000000F, 0.989000F },
    { 15500.000000F, 0.990000F },
    { 17000.000000F, 0.991000F },
    { 20000.000000F, 0.992000F },
    { 21500.000000F, 0.993000F },
    { 26000.000000F, 0.994000F },
    { 28000.000000F, 0.995000F },
    { 33500.000000F, 0.996000F },
    { 46000.000000F, 0.997000F },
    { 55000.000000F, 0.998000F },
    { 80000.000000F, 0.999000F },
    { 450000.000000F, 1.000000F }
};

static struct histmap smtp_histmap[] =
{
    { "itemsize", 333 }
};

