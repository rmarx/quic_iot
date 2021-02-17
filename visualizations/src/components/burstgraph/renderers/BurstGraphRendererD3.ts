import * as d3 from "d3";

import DeviceLogic from "@/data/utils/DeviceLogic"
import MyMath from "@/data/utils/MyMath"

enum Palette1 {
    // https://offeo.com/learn/20-pastel-spring-summer-color-palettes#fws_5f8eaba0896e1
    Green = "#CCD4BF",
    Brown = "#E7CBA9",
    Red = "#EEBAB2",
    White = "#F5F3E7",
    Pink = "#F5E2E4"

}

enum Palette2 {
    // https://offeo.com/learn/20-pastel-spring-summer-color-palettes#fws_5f8eaba091294
    Brown = "#B8A390",
    Pink = "#E6D1D2",
    DarkPink = "#d6a198",
    Grey = "#DAD5D6",
    DarkGrey = "#B2B5B9",
    Green = "#8FA2A6"
}


export class BurstGraphRendererD3 {

    private dimensions: any = {};

    private svg: any = undefined;

    private showModal:(title: string, contents:string ) => void;

    public constructor(showModalCallback:(title: string, contents:string ) => void) {
        this.showModal = showModalCallback;
    }

    public render(containerID: string, trace: any): void {

        const HTMLcontainer: HTMLElement = document.getElementById(containerID)!;
        const bounds = HTMLcontainer.getBoundingClientRect();
        const width = bounds.width;
        const height = bounds.height;

        document.getElementById(containerID)!.innerHTML = trace.trace + " with " + trace.connections.length + " connections";


        this.dimensions.margin = { top: 10, right: 10, bottom: 10, left: 10 };

        // width and height are the INTERNAL widths (so without the margins)
        this.dimensions.width = width - this.dimensions.margin.left - this.dimensions.margin.right;
        this.dimensions.height = height - this.dimensions.margin.top - this.dimensions.margin.bottom;


        // clear old rendering
        d3.select("#" + containerID).selectAll("*").remove();

        // setup container with proper size + clip path to prevent weird things from escaping the boundaries
        this.svg = d3.select("#" + containerID)
            .append("svg")
            .attr("width", width)
            .attr("height", height)
            // .attr("viewBox", [0, 0, this.dimensions.width, this.dimensions.height])
            .attr("xmlns", "http://www.w3.org/2000/svg")
            .attr("xmlns:xlink", "http://www.w3.org/1999/xlink")
            .attr("font-family", "Trebuchet-ms")
        .append("g")
            .attr("transform",
                "translate(" + (this.dimensions.margin.left + this.dimensions.width / 2) + "," + (this.dimensions.margin.top + this.dimensions.height / 2) + ")");

        const clip = this.svg.append("defs").append("SVG:clipPath")
            .attr("id", "clip")
            .append("SVG:rect")
            .attr("width", this.dimensions.width)
            .attr("height", this.dimensions.height)
            .attr("x", -this.dimensions.width / 2)
            .attr("y", -this.dimensions.height / 2)

        const svgcontainer = this.svg.append('g')
            .attr("clip-path", "url(#clip)");


        // plot circles to indicate latency ranges
        let circle = svgcontainer.append("circle")
            .attr("cx", 0 )
            .attr("cy", 0 )
            .attr("r", 50)
            .attr("stroke", Palette2.Brown)
            .attr("stroke-width", 1)
            .attr("fill","none");
        let name = svgcontainer.append("text")
            .attr("x", 50 )
            .attr("y", 0 )
            .attr("dominant-baseline", "middle")
            .style("text-anchor", "middle")
            .style("font-size", "10")
            .style("font-family", "Trebuchet MS")
            .attr("fill", Palette2.Brown)
            .text("local" )
        circle = svgcontainer.append("circle")
            .attr("cx", 0 )
            .attr("cy", 0 )
            .attr("r", 100)
            .attr("stroke", Palette2.Brown)
            .attr("stroke-width", 1)
            .attr("fill","none");
        name = svgcontainer.append("text")
            .attr("x", 100 )
            .attr("y", 0 )
            .attr("dominant-baseline", "middle")
            .style("text-anchor", "middle")
            .style("font-size", "10")
            .style("font-family", "Trebuchet MS")
            .attr("fill", Palette2.Brown)
            .text("< 20ms" );
        circle = svgcontainer.append("circle")
            .attr("cx", 0 )
            .attr("cy", 0 )
            .attr("r", 200)
            .attr("stroke", Palette2.Brown)
            .attr("stroke-width", 1)
            .attr("fill","none");
        name = svgcontainer.append("text")
            .attr("x", 200 )
            .attr("y", 0 )
            .attr("dominant-baseline", "middle")
            .style("text-anchor", "middle")
            .style("font-size", "10")
            .style("font-family", "Trebuchet MS")
            .attr("fill", Palette2.Brown)
            .text("< 100ms" );
        circle = svgcontainer.append("circle")
            .attr("cx", 0 )
            .attr("cy", 0 )
            .attr("r", 300)
            .attr("stroke", Palette2.Brown)
            .attr("stroke-width", 1)
            .attr("fill","none");
        name = svgcontainer.append("text")
            .attr("x", 300 )
            .attr("y", 0 )
            .attr("dominant-baseline", "middle")
            .style("text-anchor", "middle")
            .style("font-size", "10")
            .style("font-family", "Trebuchet MS")
            .attr("fill", Palette2.Brown)
            .text("> 100ms" );


        // we want to plot the device in the middle, with connections to the other devices around that
        // we have to plot things in "reverse" order though, because svg doesn't have z-index...

        // device.append("circle")
        //     .attr("cx", 0)
        //     .attr("cy", 0)
        //     .attr("r", 40)
        //     .attr("stroke", "black")
        //     .attr("strok-width", 3)
        //     .attr("fill", Palette2.Green);
        // device.append("text")
        //     .attr("x", 0)
        //     .attr("y", 0)
        //     .attr("dominant-baseline", "middle")
        //     .style("text-anchor", "middle")
        //     .style("font-size", "24")
        //     .style("font-family", "Trebuchet MS")
        //     .attr("fill", "#000000")

        // devices in the local network are treated differently than those outside
        let localConnections  = trace.connections.filter( (c:any) =>  DeviceLogic.isLocalConnection(c) );
        let remoteConnections = trace.connections.filter( (c:any) => !DeviceLogic.isLocalConnection(c) );

        remoteConnections = remoteConnections.concat( localConnections );

        // start with the first opened/seen connection
        remoteConnections.sort( (a:any, b:any) => a.starttime - b.starttime );

        let angleIncrement = 35;
        let currentAngle = -120;

        let deviceIP = undefined;
        if ( trace.device && trace.device.ip && trace.device.ip !== "" ) {
            deviceIP = trace.device.ip;
        }
        
        if ( !deviceIP ) {
            // need to infer the IP from the connections
            // keep track of how many times we see each internal IP. the one with the highest count is most likely to be the device 
            let ipCounters:any = {};
            for ( let connection of remoteConnections ) {
                let ip1 = connection.info.endpoint1.ip;

                if( DeviceLogic.isLocalIP(ip1) ) {
                    if ( ipCounters[ip1] === undefined )
                        ipCounters[ip1] = 0;

                    ipCounters[ip1]++;
                }

                let ip2 = connection.info.endpoint2.ip; 
                if( DeviceLogic.isLocalIP(ip2) ) {
                    if ( ipCounters[ip2] === undefined )
                        ipCounters[ip2] = 0;

                    ipCounters[ip2]++;
                }
            }

            let highestOccurence = 0;
            for ( let ip of Object.keys(ipCounters) ) {
                if( ipCounters[ip] > highestOccurence ) {
                    deviceIP = ip;
                    highestOccurence = ipCounters[ip];
                }
            }

            if ( !deviceIP ) {
                console.error("BurstGraphRendererD3: device IP could not be found somehow...", ipCounters);
            }
        }


        for ( let connection of remoteConnections ) {

            let peerColor:string = Palette2.DarkPink;
            if ( connection.info && connection.info.transport_protocol == "UDP" ) {
                peerColor = Palette2.Pink; 
            }

            let connectioncontainer = svgcontainer.append("g");

            // we want the latency of the connection to determine the distance to the device visually
            let distance = 200;

            let latency = connection.initial_RTT;
            if ( !latency && connection.median_ack_latencies ) {
                latency = Math.max( ...(Object.values(connection.median_ack_latencies) as Array<number>) );
            }
            if ( !latency ) {
                // TODO: this shouldn't happen in the new format, remove this in time
                latency = connection.estimated_RTT;
            }
            if ( !latency ) {
                latency = 25; // safe bet
                // console.error("BurstGraphRendererD3: no latency found for connection, defaulting to 25ms", connection);
            }
            
            // 50 = same network
            // 100 = < 20ms
            // 200 = < 100ms
            // 300 > 100ms
            if ( localConnections.indexOf(connection) >= 0 ) {
                distance = 50;
            }
            else if ( latency < 20 ) {
                distance = 100;
            }
            else if ( latency < 100 ) {
                distance = 200;
            }
            else {
                distance = 300;
            }

            // we want the width of the links signifying connections to scale with how much data they carried
            const getThickness = (byteCount:number) => {
                byteCount = byteCount / 1000; // go from bytes to kB

                if( byteCount === 0 ) return 0;
                if( byteCount < 100 ) return 1;
                if( byteCount < 200 ) return 4;
                if( byteCount < 500 ) return 7;
                if( byteCount < 1000 ) return 10;
                if( byteCount < 5000 ) return 20;
                
                return 10;
            }

            let incomingByteCount = 0;
            let outgoingByteCount = 0;

            let byte_ips = Object.keys(connection.byte_counts);
            for ( let ip of byte_ips ) {
                if ( ip === deviceIP )
                    outgoingByteCount = connection.byte_counts[ip];
                else 
                    incomingByteCount = connection.byte_counts[ip];
            }

            // draw the bandwidth lines first, so they don't overlap text/circles, etc.

            // want to draw the two lines next to each other, non overlapping
            // so we draw them lying down at the x-axis, on top of each other, offset in the y-direction
            // after that, we rotate them to get the correct endpoints  
            let swizzle = 2; // to prevent lines from being exactly next to each other, magic number

            let incomingDataThickness = getThickness(incomingByteCount);              
            let incomingPositionStart = MyMath.rotateAroundPoint(0, 0, distance,  -incomingDataThickness/2 - swizzle, currentAngle);
            let incomingPositionEnd   = MyMath.rotateAroundPoint(0, 0, 0.01,    -incomingDataThickness/2 - swizzle, currentAngle);
            let incomingData = connectioncontainer.append("line")
                .attr("x1", incomingPositionStart.x )
                .attr("y1", incomingPositionStart.y )
                .attr("x2", incomingPositionEnd.x )
                .attr("y2", incomingPositionEnd.y )
                .attr("stroke-width", incomingDataThickness + "px")
                .attr("stroke", peerColor)
            
            let outgoingDataThickness = getThickness(outgoingByteCount);  ;
            let outgoingPositionStart = MyMath.rotateAroundPoint(0, 0, distance,  outgoingDataThickness/2 + swizzle, currentAngle);
            let outgoingPositionEnd   = MyMath.rotateAroundPoint(0, 0, 0.01,    outgoingDataThickness/2 + swizzle, currentAngle);
            let outgoingData = connectioncontainer.append("line")
                .attr("x1", outgoingPositionStart.x )
                .attr("y1", outgoingPositionStart.y )
                .attr("x2", outgoingPositionEnd.x )
                .attr("y2", outgoingPositionEnd.y )
                .attr("stroke-width", outgoingDataThickness + "px")
                .attr("stroke", Palette2.Green)

            let position = MyMath.rotateAroundPoint(0, 0, distance, 0, currentAngle);

            // let circle = connectioncontainer.append("circle")
            //     .attr("cx", position.x )
            //     .attr("cy", position.y )
            //     .attr("r", 20)
            //     .attr("stroke", "black")
            //     .attr("strok-width", 3)
            //     .attr("fill", Palette2.Pink);

            // want to draw an arrow indicating which side initaited the connection/sent the first packet 
            // polyline expects a list of x,y coordinates
            // we draw the arrow as normal (across the "x-axis" to the right: >), then rotate it along the connecting line

            if ( connection.first_packet_from ) { 

                let createArrow = (distance:number, peerInitiated:boolean) => {
                    let arrowX = distance; 
                    let color = "";
                    let points = "";

                    if ( peerInitiated ) {
                        color = peerColor;

                        points =  "";
                        points +=  `${arrowX + 6},${0 - 6}`; // top point
                        points += ` ${arrowX    },${0    }`; // center point
                        points += ` ${arrowX + 6},${0 + 6}`; // bottom point
                    }
                    else {
                        color = Palette2.Green;
                    
                        points = "";
                        points +=  `${arrowX - 6},${0 - 6}`; // top point
                        points += ` ${arrowX    },${0    }`; // center point
                        points += ` ${arrowX - 6},${0 + 6}`; // bottom point
                    }

                    const arrow = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
                    arrow.setAttribute('points', points);
                    arrow.setAttribute('stroke-width', '4');
                    arrow.setAttribute('stroke', color);
                    arrow.setAttribute('fill', 'transparent');
                    arrow.setAttribute('transform', `rotate(${currentAngle})`);

                    return arrow;
                };

                // peer initiated
                // let arrowX = (distance / 2) - 20; // arrow needs to be closer to the device
                // let color = peerColor;
                
                // let points = "";
                // points +=  `${arrowX + 6},${0 - 6}`; // top point
                // points += ` ${arrowX    },${0    }`; // center point
                // points += ` ${arrowX + 6},${0 + 6}`; // bottom point


                // if ( connection.first_packet_from === deviceIP ) {
                //     arrowX = (distance / 2) + 20;
                //     color = Palette2.Green;
                    
                //     points = "";
                //     points +=  `${arrowX - 6},${0 - 6}`; // top point
                //     points += ` ${arrowX    },${0    }`; // center point
                //     points += ` ${arrowX - 6},${0 + 6}`; // bottom point
                // }
                // else {
                //     console.warn("Arrow should be INCOMING!", connection);
                // }
                

                // // https://stackoverflow.com/questions/2676719/calculating-the-angle-between-the-line-defined-by-two-points
                // const deltaY = currentY - target.y;
                // const deltaX = targetX  - currentX;
                // let angle = Math.atan2(deltaY, deltaX) * 180 / Math.PI; 
                // angle = -angle; // svg's rotate has the convention that clockwise rotations are positive angles, counterclockwise are negative. 


                //arrow.setAttribute('transform', `rotate(${angle},${arrowX},${target.y})`);
                if ( connection.first_packet_from === deviceIP ) {
                    connectioncontainer.node().appendChild( createArrow( (distance/2) + 10, false ) );
                    if ( connection.info.transport_protocol === "TCP" && !connection.connection_established ) { // re-used connection, express continuation with double arrows
                        connectioncontainer.node().appendChild( createArrow( (distance/2), false ) );
                    }
                }
                else {                    
                    connectioncontainer.node().appendChild( createArrow( (distance/2) - 10, true ) );
                    if ( connection.info.transport_protocol === "TCP" && !connection.connection_established ) { // re-used connection, express continuation with double arrows
                        connectioncontainer.node().appendChild( createArrow( (distance/2), true ) );
                    }
                }

                // signify connection closed with a line close to the arrow
                if ( connection.connection_closed ) {
                    let createLine = (distance:number, color:string) => {

                        color = Palette2.Green;
                    
                        let points = "";
                        points +=  `${distance},${6}`;
                        points += ` ${distance},${-6}`;

                        const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
                        line.setAttribute('points', points);
                        line.setAttribute('stroke-width', '4');
                        line.setAttribute('stroke', color);
                        line.setAttribute('fill', 'transparent');
                        line.setAttribute('transform', `rotate(${currentAngle})`);

                        return line;
                    }

                    if ( connection.first_packet_from === deviceIP ) {
                        connectioncontainer.node().appendChild( createLine( (distance/2) + 16, Palette2.Green ) );
                    }
                    else {
                        connectioncontainer.node().appendChild( createLine( (distance/2) - 16, peerColor ) );
                    }
                }
            }



            
            let ip = DeviceLogic.isLocalIP( connection.info.endpoint1.ip ) ? connection.info.endpoint2.ip + ":" + connection.info.endpoint2.port : connection.info.endpoint1.ip + ":" + connection.info.endpoint1.port;

            let ipText = this.createHTMLText( position.x, position.y, 100, 20, ip, peerColor );
            ipText.text.onclick = () => { this.showModal("Connection", JSON.stringify(connection, null, 4) ); }
            connectioncontainer.node().appendChild( ipText.container );

            // let name = connectioncontainer.append("text")
            //     .attr("x", position.x )
            //     .attr("y", position.y )
            //     .attr("dominant-baseline", "middle")
            //     .style("text-anchor", "middle")
            //     .style("font-size", "14")
            //     .style("font-family", "Trebuchet MS")
            //     .attr("fill", "#000000")
            //     .text("" + ip )

            

            currentAngle += angleIncrement;
        }

        let device = svgcontainer.append("g");
        let deviceText = this.createHTMLText( 0, 0, 150, 20, trace.device.name, Palette2.Green );
        deviceText.text.style.color = "#FFFFFF";
        deviceText.text.onclick = () => { this.showModal("Full trace", JSON.stringify(trace, null, 4) ); }
        device.node().appendChild( deviceText.container );

                
        // let transformFunction = d3.interpolateTransformSvg( "", "rotate(-110) translate(200,0)" );

        


        // connection.append("line")
        //     .attr("x1", 0)
        //     .attr("y1", 0)
        //     .attr("x2", 200)
        //     .attr("y2", 0)
        //     .attr("stroke", "black")

        // connection.append("text")
        //     .attr("x", rotatedCircle[0] )
        //     .attr("y", rotatedCircle[1] )
        //     .attr("dominant-baseline", "middle")
        //     .style("text-anchor", "middle")
        //     .style("font-size", "24")
        //     .style("font-family", "Trebuchet MS")
        //     .attr("fill", "#000000")
            // .attr("transform", function(this: any, d: any) {

            //         // let textElement = d3.select( this );

            //         // // console.log("TRANSFORMING ", d);
            //         // // var textElement = d3.select(this as any); 
            //         // // var current = textElement.attr("transform");
            //         // // var alreadyRotated = current.indexOf('rotate');
            //         // // var justTranslate = current.substring(0, alreadyRotated != -1 ? alreadyRotated : current.length);
            //         // var bbox = textElement.node().getBBox();

            //         // console.log("BBOX", bbox, textElement.node().getBoundingClientRect());

            //         // // var point = [bbox.x + 0.5*bbox.width, bbox.y + 0.5*bbox.height];
            //         // return ""; //justTranslate+"rotate("+ -value +" "+ point +")";

            //         return "rotate(110)";
            // })
            // .text( "test" ); 

        // // https://stackoverflow.com/a/44931633
        // let circleCoords = circle.node().getBoundingClientRect();
        // let matrix = connection.node().getCTM();

        // let cx = 200; // + (this.dimensions.width / 2);
        // let cy = 0;// + (this.dimensions.height / 2);

        // var x = cx * matrix.a + cy * matrix.c + matrix.e;
        // var y = cx * matrix.b + cy * matrix.d + matrix.f;

        // console.log("Circle is now at ", circleCoords, bounds, matrix, x, y);
        // console.log("Adjusted bounds", circleCoords.x - bounds.x, circleCoords.y - bounds.y);



        // let lineStart = { x : circleCoords.x - bounds.x, y : circleCoords.y - bounds.y };

        // circles.append("line")
        //     .attr("x1", rotatedCircle[0])
        //     .attr("y1", rotatedCircle[1])
        //     .attr("x2", 0)
        //     .attr("y2", 0)
        //     .attr("stroke", "black")

                // text.attr("transform", function(d){
                //     var textElement = d3.select(this);
                //     var current = textElement.attr("transform");
                //     var alreadyRotated = current.indexOf('rotate');
                //     var justTranslate = current.substring(0, alreadyRotated != -1 ? alreadyRotated : current.length);
                //     var bbox = textElement.node().getBBox();
                //     var point = [bbox.x + 0.5*bbox.width, bbox.y + 0.5*bbox.height];
                //     return justTranslate+"rotate("+ -value +" "+ point +")";
                // });

        /*
        circles
            .selectAll("rect.packet")
            .data(dataSent)
            .enter()
            .append("rect")
                .attr("x", (d:any) => xDomain(d.countStart) - packetSidePadding )
                .attr("y", (d:any) => (d.index % 2 === 0 ? 0 : packetHeight * 0.05) )
                .attr("fill", (d:any) => StreamGraphDataHelper.StreamIDToColor("" + d.streamID)[0] )
                .style("opacity", 1)
                .attr("class", "packet")
                .attr("width", (d:any) => xDomain(d.countEnd) - xDomain(d.countStart) + packetSidePadding * 2)
                .attr("height", (d:any) => packetHeight * (d.index % 2 === 0 ? 1 : 0.90))
                .style("pointer-events", "all")
                .on("mouseover", packetMouseOver)
                .on("mouseout", packetMouseOut)
                .on("click", (d:any) => { this.byteRangeRenderer.render(dataSent, dataMoved, d.streamID); this.byteRangeRenderer.zoom( this.currentDomain ); });
                */
    }

    protected createHTMLText(x: number, y: number, width: number, height: number, text: string, backgroundColor: string) {

        const textForeign = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
        textForeign.setAttribute('x', "" + (x - width/2));
        textForeign.setAttribute('y', "" + (y - height/2)); 
        textForeign.setAttribute('width',  "" + width);
        textForeign.setAttribute('height', "" + height); 
        textForeign.style.overflow = "visible";

        const textContainer = document.createElementNS("http://www.w3.org/1999/xhtml", "div");
        textContainer.style.width = "" + width + "px";
        textContainer.style.textAlign = "center";

        const textSpan = document.createElement("span");
        textSpan.textContent = text;
        textSpan.style.color = "#000000";
        textSpan.style.backgroundColor = backgroundColor;
        textSpan.style.padding = "5px";
        textSpan.style.border = "1px white";
        textSpan.style.borderStyle = "none solid";
        textSpan.style.fontFamily = "Trebuchet MS";
        textSpan.style.fontSize = "12px";

        textContainer.appendChild(textSpan);
        textForeign.appendChild(textContainer);

        return { container: textForeign, text: textSpan };
    }
}