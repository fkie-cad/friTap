//import fs from 'frida-fs';
import * as fs from "fs";
import { isAndroid } from "./process_infos.js"


// converts a hexstring to a bytearray
function hexStringToBytes(str: string): Uint8Array{
    const a = [];
    for (let i = 0, len = str.length; i < len; i += 2) {
      a.push(parseInt(str.substr(i, 2), 16));
    }
  
    return new Uint8Array(a);
  };


export function fileUpload(path: string, data: string): void{


    if(isAndroid()){
        const writeStream: any = fs.createWriteStream(path);

  writeStream.on("error", (error: Error) => {
    throw error;
  });

  writeStream.write(hexStringToBytes(data));
  writeStream.end();
    }else{

    }

    


    }








