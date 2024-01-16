import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2';
import { randomBytes } from '@noble/hashes/utils';
import { _default as _DEFAULT_WORDLIST, _default_8192 as _DEFAULT_WORDLIST_8192, wordlists } from './_wordlists';

let DEFAULT_WORDLIST: string[] | undefined = _DEFAULT_WORDLIST;
let DEFAULT_WORDLIST_8192: string[] | undefined = _DEFAULT_WORDLIST_8192;

const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED =
  'A wordlist is required but a default could not be found.\n' +
  'Please pass a 2048 word array explicitly.';

function normalize(str?: string): string {
  return (str || '').normalize('NFKD');
}

function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}

function digitToBits(input: string): string {
  // Convert input to a number
  const num = parseInt(input, 10);

  // Check if the input is within the valid range
  if (num < 0 || num > 7 || isNaN(num)) {
      throw new Error("Input must be one of 0, 1, 2, 3, 4, 5, 6, 7.");
  }

  // Convert the number to a binary string and pad to 3 bits
  const binaryString = num.toString(2).padStart(3, '0');
  return binaryString;
}

function bitsToDigit(binary: string): string {
  // Check if the input is a valid 3-bit string
  if (binary.length !== 3 || !/^[01]+$/.test(binary)) {
    throw new Error("Input must a 3 bit string");
  }
  // Convert binary string to integer
  const integerValue = parseInt(binary, 2);
  return integerValue.toString();
}

function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

function bytesToBinary(bytes: number[]): string {
  return bytes.map((x: number): string => lpad(x.toString(2), '0', 8)).join('');
}

function deriveChecksumBits(entropyBuffer: Buffer): string {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = sha256(Uint8Array.from(entropyBuffer));
  return bytesToBinary(Array.from(hash)).slice(0, CS);
}

function salt(password?: string): string {
  return 'mnemonic' + (password || '');
}

export function mnemonicToSeedSync(
  mnemonic: string,
  password?: string,
): Buffer {
  const mnemonicBuffer = Uint8Array.from(
    Buffer.from(normalize(mnemonic), 'utf8'),
  );
  const saltBuffer = Uint8Array.from(
    Buffer.from(salt(normalize(password)), 'utf8'),
  );
  const res = pbkdf2(sha512, mnemonicBuffer, saltBuffer, {
    c: 2048,
    dkLen: 64,
  });
  return Buffer.from(res);
}

export function mnemonicToSeed(
  mnemonic: string,
  password?: string,
): Promise<Buffer> {
  const mnemonicBuffer = Uint8Array.from(
    Buffer.from(normalize(mnemonic), 'utf8'),
  );
  const saltBuffer = Uint8Array.from(
    Buffer.from(salt(normalize(password)), 'utf8'),
  );
  return pbkdf2Async(sha512, mnemonicBuffer, saltBuffer, {
    c: 2048,
    dkLen: 64,
  }).then((res: Uint8Array): Buffer => Buffer.from(res));
}

export function mnemonicToEntropy(
  mnemonic: string,
  wordlist?: string[],
): string {
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const words = normalize(mnemonic).split(' ');
  // if (words.length % 3 !== 0) {
  //   throw new Error(INVALID_MNEMONIC);
  // }
  // console.log(words);
  // console.log(wordlist.length);
  // console.log(mnemonic);

  // convert word indices to 13 bit binary strings
  const bits = words
    .map(
      (word: string): string => {
        // console.log(word);
        let res: string[] = word.split("-");
        let parsed = res[0] + "-";
        // console.log('parsed', parsed);

        const index = wordlist!.indexOf(parsed);
        const digit = res[1];
        if (index === -1) {
          throw new Error(INVALID_MNEMONIC);
        }

        const s0 = lpad(index.toString(2), '0', 13);
        const s1 = digitToBits(digit);
        const combined = s0 + s1;
        // console.log('combined', combined);
        return combined;
      },
    )
    .join('');

  // split the binary string into ENT/CS
  // const dividerIndex = Math.floor(bits.length / 33) * 32;
  // const entropyBits = bits.slice(0, dividerIndex);
  // const checksumBits = bits.slice(dividerIndex);
  const entropyBits = bits;

  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g)!.map(binaryToByte);
  // if (entropyBytes.length < 16) {
  //   throw new Error(INVALID_ENTROPY);
  // }
  // if (entropyBytes.length > 32) {
  //   throw new Error(INVALID_ENTROPY);
  // }
  if (entropyBytes.length !== 16) {
    throw new Error(INVALID_ENTROPY);
  }

  const entropy = Buffer.from(entropyBytes);
  // const newChecksum = deriveChecksumBits(entropy);
  // if (newChecksum !== checksumBits) {
  //   throw new Error(INVALID_CHECKSUM);
  // }
  const hex = entropy.toString('hex');
  console.log('entropytk', hex);
  return hex;
}

export function entropyToMnemonic(
  entropy: Buffer | string,
  wordlist?: string[],
): string {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex');
  }
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  // 128 <= ENT <= 256
  // if (entropy.length < 16) {
  //   throw new TypeError(INVALID_ENTROPY);
  // }
  // if (entropy.length > 32) {
  //   throw new TypeError(INVALID_ENTROPY);
  // }
  if (entropy.length !== 16) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const entropyBits = bytesToBinary(Array.from(entropy));
  // const checksumBits = deriveChecksumBits(entropy);

  // const bits = entropyBits + checksumBits;
  const bits = entropyBits;
  const chunks = bits.match(/(.{1,16})/g)!;
  // console.log('chunk', chunks.length);
  const words = chunks.map(
    (binary: string): string => {
    // Extract the first 13 bits
    const bits13 = binary.slice(0, 13);
    const index = binaryToByte(bits13);
    const word = wordlist![index];

    // Extract the last 3 bits
    const bits3 = binary.slice(13);
    const digit = bitsToDigit(bits3);
    const combined = word + digit;
      return combined;
    },
  );

  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
}

export function generateMnemonic(
  strength?: number,
  rng?: (size: number) => Buffer,
  wordlist?: string[],
): string {
  strength = strength || 128;
  // if (strength % 32 !== 0) {
  //   throw new TypeError(INVALID_ENTROPY);
  // }
  if (strength !== 128 ) {
    throw new TypeError(INVALID_ENTROPY);
  }
  rng = rng || ((size: number): Buffer => Buffer.from(randomBytes(size)));
  return entropyToMnemonic(rng(strength / 8), wordlist);
}

export function validateMnemonic(
  mnemonic: string,
  wordlist?: string[],
): boolean {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }

  return true;
}

export function setDefaultWordlist(language: string): void {
  const result = wordlists[language];
  if (result) {
    DEFAULT_WORDLIST = result;
  } else {
    throw new Error('Could not find wordlist for language "' + language + '"');
  }
}

export function getDefaultWordlist(): string {
  if (!DEFAULT_WORDLIST) {
    throw new Error('No Default Wordlist set');
  }
  return Object.keys(wordlists).filter(
    (lang: string): boolean => {
      if (lang === 'JA' || lang === 'EN') {
        return false;
      }
      return wordlists[lang].every(
        (word: string, index: number): boolean =>
          word === DEFAULT_WORDLIST![index],
      );
    },
  )[0];
}

export function convertLegacyToCompressed(
  mnemonic: string,
  wordlistLegacy?: string[],
  wordlist8192?: string[]
): string {
  wordlistLegacy = wordlistLegacy || DEFAULT_WORDLIST;
  wordlist8192 = wordlist8192 || DEFAULT_WORDLIST_8192;
  if (!wordlistLegacy || !wordlist8192) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const legacyWords = normalize(mnemonic).split(' ');
  if (legacyWords.length !== 12) {
    throw new Error("only 12 word legacy mnemonics are supported for conversion");
  }
  let entropy = legacyMnemonicToEntropyBytes(mnemonic, wordlistLegacy);
  return entropyToMnemonic(entropy, wordlist8192)
}

export function convertCompressedToLegacy(
  mnemonic: string,
  wordlistLegacy?: string[],
  wordlist8192?: string[]
): string {
  wordlistLegacy = wordlistLegacy || DEFAULT_WORDLIST;
  wordlist8192 = wordlist8192 || DEFAULT_WORDLIST_8192;
  if (!wordlistLegacy || !wordlist8192) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const compressedWords = normalize(mnemonic).split(' ');
  if (compressedWords.length !== 8) {
    throw new Error("Compressed mneomonics must be length 8");
  }
  let entropy = mnemonicToEntropy(mnemonic, wordlist8192);
  return entropyToLegacyMnemonic(entropy, wordlistLegacy)
}

export function entropyToLegacyMnemonic(
  entropy: Buffer | string,
  wordlist?: string[],
): string {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex');
  }
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksumBits = deriveChecksumBits(entropy);

  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g)!;
  const words = chunks.map(
    (binary: string): string => {
      const index = binaryToByte(binary);
      return wordlist![index];
    },
  );

  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
}

export function legacyMnemonicToEntropyBytes(
  mnemonic: string,
  wordlist?: string[],
): string {
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }

  // convert word indices to 11 bit binary strings
  const bits = words
    .map(
      (word: string): string => {
        const index = wordlist!.indexOf(word);
        if (index === -1) {
          throw new Error(INVALID_MNEMONIC);
        }

        return lpad(index.toString(2), '0', 11);
      },
    )
    .join('');

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g)!.map(binaryToByte);
  if (entropyBytes.length !== 16) {
    throw new Error(INVALID_ENTROPY);
  }
  // if (entropyBytes.length > 32) {
  //   throw new Error(INVALID_ENTROPY);
  // }
  // if (entropyBytes.length % 4 !== 0) {
  //   throw new Error(INVALID_ENTROPY);
  // }
  const entropy = Buffer.from(entropyBytes);
  const newChecksum = deriveChecksumBits(entropy);
  if (newChecksum !== checksumBits) {
    throw new Error(INVALID_CHECKSUM);
  }

  return entropy.toString('hex');
}

export { wordlists } from './_wordlists';
