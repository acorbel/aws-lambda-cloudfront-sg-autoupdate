'use strict';

const SERVICE = 'CLOUDFRONT';
const RULE_PER_SG = 50;
const PORT = 8443;

const TAGS = [{
    Name: 'tag-key',
    Values: ['Name'],
}, {
    Name: 'tag-value',
    Values: ['cloudfront'],
}, {
    Name: 'tag-key',
    Values: ['AutoUpdate'],
}, {
    Name: 'tag-value',
    Values: ['true'],
}, {
    Name: 'tag-key',
    Values: ['Port'],
}, {
    Name: 'tag-value',
    Values: [String(PORT)],
}];


const https = require('https');
const crypto = require('crypto');
const AwsEc2 = require('aws-sdk/clients/ec2');
const EC2 = new AwsEc2();

async function handler({ Records }) {
    if (!PORT) throw new Error('missing port');

    const { url, md5 } = JSON.parse(Records[0].Sns.Message);

    const { prefixes } = await getIpsFromUrl(url, md5);
    const cloudfrontRanges = prefixes.filter(i => i.service === SERVICE).map(i => i.ip_prefix);
    console.info('IPs found', cloudfrontRanges.length);

    let { SecurityGroups } = await EC2.describeSecurityGroups({ Filters: TAGS }).promise();
    console.info('SecurityGroups', SecurityGroups.map(i => i.GroupId));
    
    if (cloudfrontRanges.length > RULE_PER_SG * SecurityGroups.length) throw new Error('not enough security groups');
    
    let revokesDone = false;

    // cleanup old prefixes
    for (const sg of SecurityGroups) {
        const toRevoke = [];
        
        sg.IpPermissions.forEach((ipPermission) => {
            if (ipPermission.FromPort == PORT && ipPermission.ToPort == PORT) { // string vs number
            
                const IpRangesToRemove = [];
                
                for (const { CidrIp } of ipPermission.IpRanges) {
                    const idx = cloudfrontRanges.indexOf(CidrIp);
                    if (idx > -1) cloudfrontRanges.splice(idx, 1); // no need to update
                    else IpRangesToRemove.push({ CidrIp });
                }
                if (IpRangesToRemove.length) toRevoke.push({ FromPort: PORT, ToPort: PORT, IpProtocol: 'tcp', IpRanges: IpRangesToRemove });
                
            } else toRevoke.push({ FromPort: ipPermission.FromPort, ToPort: ipPermission.ToPort, IpProtocol: ipPermission.IpProtocol, IpRanges: ipPermission.IpRanges });
        });
        
        console.info('Revokation', sg.GroupId, toRevoke.length);
        if (toRevoke.length) {
            await EC2.revokeSecurityGroupIngress({
                GroupId: sg.GroupId,
                IpPermissions: toRevoke,
            }).promise();
            revokesDone = true;
        }
    }

    if (revokesDone === true) {
        const data = await EC2.describeSecurityGroups({ Filters: TAGS }).promise();
        SecurityGroups = data.SecurityGroups;
    }


    for (const sg of SecurityGroups) {
        if (cloudfrontRanges.length === 0) {
            console.info('Addition', sg.GroupId, 0);
        } else {
            const slots = sg.IpPermissions.length ? RULE_PER_SG - sg.IpPermissions[0].IpRanges.length : 50;
            if (slots > 0) {
                const IpRanges = cloudfrontRanges.splice(0, slots);
                await EC2.authorizeSecurityGroupIngress({
                    GroupId: sg.GroupId,
                    IpPermissions: [{
                        ToPort: PORT,
                        FromPort: PORT,
                        IpRanges: IpRanges.map(r => ({ CidrIp: r })),
                        IpProtocol: 'tcp',
                    }],
                }).promise();
                
                console.info('Addition', sg.GroupId, IpRanges.length);
            }
        }
    }
}

async function getIpsFromUrl(url, md5) {
    console.info('getIpsFromUrl');
    return new Promise((resolve, reject) => {
        https
            .get(url, (res) => {
                const { statusCode } = res;
                const contentType = res.headers['content-type'];

                let error;
                if (statusCode !== 200) error = new Error('Request Failed.\n' + `Status Code: ${statusCode}`);
                else if (!/^application\/json/.test(contentType)) error = new Error('Invalid content-type.\n' + `Expected application/json but received ${contentType}`);

                if (error) {
                    console.error(error.message);
                    // consume response data to free up memory
                    res.resume();
                    return;
                }

                res.setEncoding('utf8');
                let rawData = '';
                res.on('data', (chunk) => { rawData += chunk; });
                res.on('end', () => {
                    if (error) return reject(error);
                    try {
                        const hash = crypto.createHash('md5').update(rawData).digest('hex');
                        if (hash !== md5) return reject(new Error('hash'));
                        const parsedData = JSON.parse(rawData);
                        resolve(parsedData);
                    } catch (e) {
                        console.error(e.message);
                        reject(e);
                    }
                });
            })
            .on('error', (e) => {
                console.error(`Got error: ${e.message}`);
                reject(e);
            });
    });
}

module.exports.handler = handler;