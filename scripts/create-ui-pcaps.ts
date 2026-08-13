import { mkdir, writeFile } from "node:fs/promises";

function tcpFrame(index: number, payloadLength: number) {
  const frame = Buffer.alloc(14 + 20 + 20 + payloadLength);
  frame.writeUInt16BE(0x0800, 12); frame[14] = 0x45; frame.writeUInt16BE(20 + 20 + payloadLength, 16); frame[23] = 6;
  [10, 30, 0, index + 1].forEach((value, offset) => { frame[26 + offset] = value; }); [203, 0, 113, 10].forEach((value, offset) => { frame[30 + offset] = value; });
  frame.writeUInt16BE(45000 + index, 34); frame.writeUInt16BE(443, 36); frame[46] = 0x50;
  for (let offset = 0; offset < payloadLength; offset += 1) frame[54 + offset] = (index * 19 + offset) % 255;
  return frame;
}
function pcap(payloadLength: number) {
  const global = Buffer.alloc(24); global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20);
  const entries: Buffer[] = []; for (let index = 0; index < 6; index += 1) { const frame = tcpFrame(index, payloadLength + index * 8); const header = Buffer.alloc(16); header.writeUInt32LE(1710001000 + index, 0); header.writeUInt32LE(index * 180000, 4); header.writeUInt32LE(frame.length, 8); header.writeUInt32LE(frame.length, 12); entries.push(header, frame); }
  return Buffer.concat([global, ...entries]);
}

const output = "/home/ubuntu/Downloads/trafficguard-ui-samples";
await mkdir(output, { recursive: true });
await Promise.all([
  writeFile(`${output}/ui-benign.pcap`, pcap(32)),
  writeFile(`${output}/ui-c2-channel.pcap`, pcap(240)),
  writeFile(`${output}/ui-data-exfiltration.pcap`, pcap(1300)),
  writeFile(`${output}/ui-detection-target.pcap`, pcap(1450)),
]);
console.log(output);
