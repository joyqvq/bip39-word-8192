"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// import { sha256 } from '@noble/hashes/sha256';
const sha512_1 = require("@noble/hashes/sha512");
const pbkdf2_1 = require("@noble/hashes/pbkdf2");
const utils_1 = require("@noble/hashes/utils");
const _wordlists_1 = require("./_wordlists");
let DEFAULT_WORDLIST = _wordlists_1._default;
const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
// const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED = 'A wordlist is required but a default could not be found.\n' +
    'Please pass a 2048 word array explicitly.';
function normalize(str) {
    return (str || '').normalize('NFKD');
}
function lpad(str, padString, length) {
    while (str.length < length) {
        str = padString + str;
    }
    return str;
}
function digitToBits(input) {
    console.log(input);
    // Convert input to a number
    const num = parseInt(input, 10);
    // Check if the input is within the valid range
    if (num < 0 || num > 7 || isNaN(num)) {
        throw new Error("Input must be one of 0, 1, 2, 3, 4, 5, 6, 7.");
    }
    // Convert the number to a binary string and pad to 3 bits
    const binaryString = num.toString(2).padStart(3, '0');
    console.log(binaryString);
    return binaryString;
}
function binaryToByte(bin) {
    return parseInt(bin, 2);
}
function bytesToBinary(bytes) {
    return bytes.map((x) => lpad(x.toString(2), '0', 8)).join('');
}
// function deriveChecksumBits(entropyBuffer: Buffer): string {
//   const ENT = entropyBuffer.length * 8;
//   const CS = ENT / 32;
//   const hash = sha256(Uint8Array.from(entropyBuffer));
//   return bytesToBinary(Array.from(hash)).slice(0, CS);
// }
function salt(password) {
    return 'mnemonic' + (password || '');
}
function mnemonicToSeedSync(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize(mnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
    const res = pbkdf2_1.pbkdf2(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    });
    return Buffer.from(res);
}
exports.mnemonicToSeedSync = mnemonicToSeedSync;
function mnemonicToSeed(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize(mnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
    return pbkdf2_1.pbkdf2Async(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    }).then((res) => Buffer.from(res));
}
exports.mnemonicToSeed = mnemonicToSeed;
function mnemonicToEntropy(mnemonic, wordlist) {
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
        .map((word) => {
        // console.log(word);
        let res = word.split("-");
        let parsed = res[0] + "-";
        // console.log('parsed', parsed);
        const index = wordlist.indexOf(parsed);
        const digit = res[1];
        if (index === -1) {
            throw new Error(INVALID_MNEMONIC);
        }
        const s0 = lpad(index.toString(2), '0', 13);
        const s1 = digitToBits(digit);
        const combined = s0 + s1;
        // console.log('combined', combined);
        return combined;
    })
        .join('');
    // split the binary string into ENT/CS
    // const dividerIndex = Math.floor(bits.length / 33) * 32;
    // const entropyBits = bits.slice(0, dividerIndex);
    // const checksumBits = bits.slice(dividerIndex);
    const entropyBits = bits;
    console.log('entropyBitstk', entropyBits);
    // calculate the checksum and compare
    const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
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
exports.mnemonicToEntropy = mnemonicToEntropy;
function entropyToMnemonic(entropy, wordlist) {
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
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map((binary) => {
        const index = binaryToByte(binary);
        return wordlist[index];
    });
    return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
        ? words.join('\u3000')
        : words.join(' ');
}
exports.entropyToMnemonic = entropyToMnemonic;
function generateMnemonic(strength, rng, wordlist) {
    strength = strength || 128;
    // if (strength % 32 !== 0) {
    //   throw new TypeError(INVALID_ENTROPY);
    // }
    if (strength !== 128) {
        throw new TypeError(INVALID_ENTROPY);
    }
    rng = rng || ((size) => Buffer.from(utils_1.randomBytes(size)));
    return entropyToMnemonic(rng(strength / 8), wordlist);
}
exports.generateMnemonic = generateMnemonic;
function validateMnemonic(mnemonic, wordlist) {
    try {
        mnemonicToEntropy(mnemonic, wordlist);
    }
    catch (e) {
        return false;
    }
    return true;
}
exports.validateMnemonic = validateMnemonic;
function setDefaultWordlist(language) {
    const result = _wordlists_1.wordlists[language];
    if (result) {
        DEFAULT_WORDLIST = result;
    }
    else {
        throw new Error('Could not find wordlist for language "' + language + '"');
    }
}
exports.setDefaultWordlist = setDefaultWordlist;
function getDefaultWordlist() {
    if (!DEFAULT_WORDLIST) {
        throw new Error('No Default Wordlist set');
    }
    return Object.keys(_wordlists_1.wordlists).filter((lang) => {
        if (lang === 'JA' || lang === 'EN') {
            return false;
        }
        return _wordlists_1.wordlists[lang].every((word, index) => word === DEFAULT_WORDLIST[index]);
    })[0];
}
exports.getDefaultWordlist = getDefaultWordlist;
var _wordlists_2 = require("./_wordlists");
exports.wordlists = _wordlists_2.wordlists;
