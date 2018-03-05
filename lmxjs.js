/*
 * The MIT License (MIT)
 * 
 * Copyright (C) 2018 Quantum HPC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the “Software”), to deal in the 
 * Software without restriction, including without limitation the rights to use, copy, 
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to the 
 * following conditions:

 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.

 * The Software is provided “as is”, without warranty of any kind, express or implied, 
 * including but not limited to the warranties of merchantability, fitness for a particular 
 * purpose and noninfringement. In no event shall the authors or copyright holders be 
 * liable for any claim, damages or other liability, whether in an action of contract, 
 * tort or otherwise, arising from, out of or in connection with the software or the use 
 * or other dealings in the Software.
*/
var cproc = require('child_process');
var spawn = cproc.spawnSync;
var fs = require('fs');
var path = require('path');

// Regex for lmstat output
var featureRegEx=/^\s*Feature\:\s*([^\s]+)\s*Version\:\s*([0-9]+\.[0-9]+)\s*Vendor\:\s*([^\s]+)$/;
var dateRegEx=/^\s*Start\sdate\:\s*([0-9]{4}\-[0-9]{2}\-[0-9]{2})\s*Expire\sdate\:\s*([0-9]{4}\-[0-9]{2}\-[0-9]{2})/;
var keyRegEx=/^\s*Key\stype\:\s*([^\s]+)\s*License\ssharing\:\s*(.+)/;
var totalRegEx=/^\s*([0-9]+)\sof\s([0-9]+)\slicense\(s\)\sused/;
var denialRegEx=/^\s*([0-9]+)\sdenial\(s\)\sin\slast\s[0-9]+\shours/;
var userTokenRegEx=/\s*([0-9]+)\slicense\(s\)\sused\sby\s(.+?)@([^\s]+)\s+\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]/;
var userTokenTimeRegEx=/\s*Login\stime\:\s*([0-9]{4}\-[0-9]{2}\-[0-9]{2})\s+([0-9]{2}\:[0-9]{2})\s+Checkout\stime\:\s*([0-9]{4}\-[0-9]{2}\-[0-9]{2})\s+([0-9]{2}\:[0-9]{2})/;

function lmxstat(lmxConfig, callback){
    var result = {};
    var tokenFeature, tokenVersion, tokenVendor;
    var lmxCmd = lmxConfig.cmd.trim().split(/\s/g);
    
    // Create Stream
    var output = [];
    if (lmxConfig.serverURL[0] === 'test'){
        var outputFile = fs.readFileSync(lmxConfig.serverURL[1],'utf8');
        output.stdout = outputFile;
    }else{
        var url = lmxConfig.serverURL.split("@");
        lmxCmd.push("-host");
        lmxCmd.push(url[1]);
        lmxCmd.push("-port");
        lmxCmd.push(url[0]);
        output = spawn(path.resolve(lmxConfig.binary + (/^win/.test(process.platform) ? (!lmxConfig.binary.endsWith(".exe") ? '.exe' : '') : '')), lmxCmd, { encoding : 'utf8' });
    }
    
    // Invalid lmutil binary
    if (output.error){
      return callback(new Error(output.error));
    }
    // Transmit the error if any
    if (output.stderr){
      return callback(new Error(output.stderr.replace(/\n/g,"")));
    }
    // Treat output
    output = output.stdout.split('\n');
    
    for (var i=0; i<output.length; i++){
        // Line by line
        var line = output[i];
        var m,n,o,p,q,r,s;
        // Feature line
        m = line.match(featureRegEx);
        if (m) {
            tokenFeature = m[1];
            tokenVersion = m[2];
            tokenVendor  = m[3];
            
            // Get next line
            var dateLine = output[i+1];
            var keyLine = output[i+2];
            var totalLine = output[i+4];
            n = dateLine.match(dateRegEx);
            o = keyLine.match(keyRegEx);
            p = totalLine.match(totalRegEx);
            if (n && o && p) {
                // Push the feature
                result[tokenFeature] = {
                    "total"         :   p[2],
                    "used"          :   p[1],
                    "free"          :   p[2]-p[1],
                    "version"       :   tokenVersion,
                    "vendor"        :   tokenVendor,
                    "type"          :   o[1],
                    "sharing"       :   o[2],
                    "start"         :   n[1],
                    "expiry"        :   n[2],
                    "tokens":[]
                };
                i+=4;
            }
        }else{
            q = line.match(denialRegEx);
            if (q) {
                result[tokenFeature].denial = q[1];
            }else{
                r = line.match(userTokenRegEx);
                if (r) {
                    var tokenTimeLine = output[i+1];
                    s = tokenTimeLine.match(userTokenTimeRegEx);
                    if(s){
                        // Push the token
                        result[tokenFeature].tokens.push({
                            "username"      : r[2],
                            "machine"       : r[3],
                            "started"       : s[1] + " at " + s[2],
                            "tokens"        : r[1]
                        });
                        i=i+2;
                    }
                }
            }
        }
    }

    // Return result table
    return callback(null, result);
}

module.exports = {
    lmxstat :   lmxstat
};
