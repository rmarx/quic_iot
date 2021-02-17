
export default class NDJSONParser {

    public static async parseString ( input:string ) : Promise < Array<any> > {
         // we only have a streaming parser for this, so even if we have a string, we need to transform it to a stream
         const blob = new Blob([input]);
         let contentStream = new Response(blob).body!;

         return NDJSONParser.parse( contentStream );
    }

    public static async parse( inputStream:ReadableStream ) : Promise< Array<any> > {

        let contents = await NDJSONParser.parseNDJSON( inputStream );

        return contents;
    }

    protected static async parseNDJSON( inputStream:ReadableStream ) : Promise<Array<any>> {

        let resolver:any = undefined;
        let rejecter:any = undefined;

        const output = new Promise<Array<any>>( (resolve, reject) => {
            resolver = resolve;
            rejecter = reject;
        });

        const entries:Array<any> = [];

        const jsonStream = NDJSONParser.createNewlineTransformer( inputStream );

        const streamReader = jsonStream.getReader(); 
        let read:any = undefined;

        streamReader.read().then( read = ( result:any ) => {

            // at the end of the stream, this function is called one last time 
            // with result.done set and an empty result.value
            if ( result.done ) {
                resolver( entries );

                return;
            }

            // use destructuring instead of concat to merge the objects, 
            // see https://dev.to/uilicious/javascript-array-push-is-945x-faster-than-array-concat-1oki
            entries.push( ...result.value );

            streamReader.read().then( read );
        } );

        return output;
    }

    // this code was taken largely from the can-ndjson-stream project (https://www.npmjs.com/package/can-ndjson-stream)
    // that project however surfaces each object individually, which incurs quite a large message passing overhead from the transforming stream
    // to the reading stream.
    // Our custom version here instead batches all read objects from a single chunk and propagates those up in 1 time, which is much faster for our use case.

    // copyright notice for this function:
    /*
        The MIT License (MIT)

        Copyright 2017 Justin Meyer (justinbmeyer@gmail.com), Fang Lu
        (cc2lufang@gmail.com), Siyao Wu (wusiyao@umich.edu), Shang Jiang
        (mrjiangshang@gmail.com)

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
    */
    protected static createNewlineTransformer( inputStream:ReadableStream ):ReadableStream {

        let is_reader:ReadableStreamReader|undefined = undefined;
        let cancellationRequest:boolean = false;

        let readLineCount = 0;

        return new ReadableStream({
            start: (controller) => {
                const reader = inputStream.getReader();
                is_reader = reader;

                const decoder = new TextDecoder();
                let data_buf = "";

                reader.read().then(function processResult(result:any):any {

                    // console.log("parseNDJSON:parse ", result);

                    // at the end of the stream, this function is called one last time 
                    // with result.done set and an empty result.value
                    if (result.done) {
                        if (cancellationRequest) {
                            // Immediately exit
                            return;
                        }

                        // try to process the last part of the file if possible
                        data_buf = data_buf.trim();
                        if (data_buf.length !== 0) {
                            ++readLineCount;

                            try {
                                const data_l = JSON.parse(data_buf);
                                controller.enqueue( [data_l] ); // need to wrap in array, since that's what calling code expects
                            } 
                            catch (e) {
                                console.error("NDJSONParser: line #" + readLineCount + " was invalid JSON. Skipping and continuing.", data_buf);
                                // // TODO: what does this do practically? We probably want to (silently?) ignore errors?
                                // controller.error(e);
                                // return;
                            }
                        }

                        controller.close();

                        return;
                    }

                    const data = decoder.decode(result.value, {stream: true});
                    data_buf += data;

                    const lines = data_buf.split("\n");

                    const output = []; // batch results together to reduce message passing overhead

                    for ( let i = 0; i < lines.length - 1; ++i) {

                        const l = lines[i].trim();
                        
                        if (l.length > 0) {
                            ++readLineCount;

                            try {
                                const data_line = JSON.parse(l);
                                // controller.enqueue(data_line) would immediately pass the single read object on, but we batch it instead on the next line
                                output.push( data_line );
                            } 
                            catch (e) {
                                console.error("NDJSONParser: line #" + readLineCount + " was invalid JSON. Skipping and continuing.", l);

                                // // TODO: what does this do practically? We probably want to (silently?) ignore errors?
                                // controller.error(e);
                                // cancellationRequest = true;
                                // reader.cancel();

                                // return;
                            }
                        }
                    }
                    data_buf = lines[lines.length - 1];

                    controller.enqueue( output );

                    return reader.read().then(processResult);
                });

            },

            cancel: (reason) => {
                console.warn("NDJSONParser:parseNDJSON : Cancel registered due to ", reason);

                cancellationRequest = true;

                if ( is_reader !== undefined ) {
                    is_reader.cancel();
                }
            },
        },
        // TODO: we tried to optimize a bit with this, but it doesn't seem to work (printing chunks above gives chunks of 65K, not 260K)
        // didn't immediately find a good solution for this though, seems like chunk-sizing APIs aren't well supported yet in browsers
        {
            highWaterMark: 4, // read up to 1 chunk of the following size 
            size: (chunk) => { return 262144; },
        });
    }
}