// src/utils/protobufDecoder.ts

// 一个极简的 Protobuf Raw Decoder (类似 protoc --decode_raw)
export interface ProtoField {
  id: number;
  type: number; // Wire Type
  value: any;
  subMessage?: ProtoField[]; // 如果是嵌套消息
}

export function decodeProto(buffer: Uint8Array): ProtoField[] {
  const result: ProtoField[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    try {
      const tag = readVarint(buffer, offset);
      offset = tag.newOffset;
      const wireType = tag.value & 0x07;
      const fieldId = tag.value >> 3;

      let value: any;
      let subMessage: ProtoField[] | undefined;

      if (wireType === 0) {
        // Varint
        const val = readVarint(buffer, offset);
        value = val.value;
        offset = val.newOffset;
      } else if (wireType === 2) {
        // Length-delimited (String, Bytes, Embedded Message)
        const len = readVarint(buffer, offset);
        offset = len.newOffset;
        const bytes = buffer.slice(offset, offset + len.value);
        offset += len.value;

        // 尝试递归解析子消息
        try {
          if (bytes.length > 0) {
            subMessage = decodeProto(bytes);
          }
        } catch (e) {}

        // 尝试转 String
        const textDecoder = new TextDecoder("utf-8", { fatal: true });
        try {
          value = textDecoder.decode(bytes);
        } catch (e) {
          // 转不了字符串就展示 Hex
          value = `(Bytes) ${Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ")}`;
        }
      } else if (wireType === 1) {
        // 64-bit
        offset += 8;
        value = "(64-bit fixed)";
      } else if (wireType === 5) {
        // 32-bit
        offset += 4;
        value = "(32-bit fixed)";
      } else {
        // 不支持的类型，跳出
        break;
      }

      result.push({ id: fieldId, type: wireType, value, subMessage });
    } catch (e) {
      break;
    }
  }
  return result;
}

function readVarint(buffer: Uint8Array, offset: number) {
  let value = 0;
  let shift = 0;
  let byte = 0;
  do {
    if (offset >= buffer.length) throw new Error("EOF");
    byte = buffer[offset++];
    value |= (byte & 0x7f) << shift;
    shift += 7;
  } while (byte & 0x80);
  return { value, newOffset: offset };
}
