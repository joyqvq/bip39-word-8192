"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sha256_1 = require("@noble/hashes/sha256");
const sha512_1 = require("@noble/hashes/sha512");
const pbkdf2_1 = require("@noble/hashes/pbkdf2");
const utils_1 = require("@noble/hashes/utils");
const _wordlists_1 = require("./_wordlists");
let DEFAULT_WORDLIST = _wordlists_1._default;
let DEFAULT_WORDLIST_8192 = _wordlists_1._default_8192;
const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
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
    // Convert input to a number
    const num = parseInt(input, 10);
    // Check if the input is within the valid range
    if (num < 0 || num > 7 || isNaN(num)) {
        throw new Error('Input must be one of 0, 1, 2, 3, 4, 5, 6, 7.');
    }
    // Convert the number to a binary string and pad to 3 bits
    const binaryString = num.toString(2).padStart(3, '0');
    return binaryString;
}
function bitsToDigit(binary) {
    // Check if the input is a valid 3-bit string
    if (binary.length !== 3 || !/^[01]+$/.test(binary)) {
        throw new Error('Input must a 3 bit string');
    }
    // Convert binary string to integer
    const integerValue = parseInt(binary, 2);
    return integerValue.toString();
}
function binaryToByte(bin) {
    return parseInt(bin, 2);
}
function bytesToBinary(bytes) {
    return bytes.map((x) => lpad(x.toString(2), '0', 8)).join('');
}
function deriveChecksumBits(entropyBuffer) {
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    const hash = sha256_1.sha256(Uint8Array.from(entropyBuffer));
    return bytesToBinary(Array.from(hash)).slice(0, CS);
}
function salt(password) {
    return 'mnemonic' + (password || '');
}
function mnemonicToSeedSync(mnemonic, password) {
    const entropy = mnemonicToEntropy(mnemonic);
    const legacyMnemonic = entropyToLegacyMnemonic(entropy);
    const legacyMnemonicBuffer = Uint8Array.from(Buffer.from(normalize(legacyMnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
    const res = pbkdf2_1.pbkdf2(sha512_1.sha512, legacyMnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    });
    return Buffer.from(res);
}
exports.mnemonicToSeedSync = mnemonicToSeedSync;
function mnemonicToSeed(mnemonic, password) {
    const entropy = mnemonicToEntropy(mnemonic);
    const legacyMnemonic = entropyToLegacyMnemonic(entropy);
    const legacyMnemonicBuffer = Uint8Array.from(Buffer.from(normalize(legacyMnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
    return pbkdf2_1.pbkdf2Async(sha512_1.sha512, legacyMnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    }).then((res) => Buffer.from(res));
}
exports.mnemonicToSeed = mnemonicToSeed;
function mnemonicToEntropy(mnemonic, wordlist) {
    wordlist = wordlist || DEFAULT_WORDLIST_8192;
    if (!wordlist) {
        throw new Error(WORDLIST_REQUIRED);
    }
    const words = normalize(mnemonic).split(' ');
    let digits = '';
    let bits = words
        .map((word) => {
        const res = word.split('-');
        const parsed = res[0] + '-';
        const index = wordlist.indexOf(parsed);
        const digit = res[1];
        if (index === -1) {
            throw new Error(INVALID_MNEMONIC);
        }
        const s0 = lpad(index.toString(2), '0', 13);
        const s1 = digitToBits(digit);
        digits += s1;
        return s0;
    })
        .join('');
    bits += digits;
    const entropyBits = bits;
    const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
    if (entropyBytes.length !== 16) {
        throw new Error(INVALID_ENTROPY);
    }
    const entropy = Buffer.from(entropyBytes);
    const hex = entropy.toString('hex');
    return hex;
}
exports.mnemonicToEntropy = mnemonicToEntropy;
function entropyToMnemonic(entropy, wordlist) {
    if (!Buffer.isBuffer(entropy)) {
        entropy = Buffer.from(entropy, 'hex');
    }
    wordlist = wordlist || DEFAULT_WORDLIST_8192;
    if (!wordlist) {
        throw new Error(WORDLIST_REQUIRED);
    }
    if (entropy.length !== 16) {
        throw new TypeError(INVALID_ENTROPY);
    }
    const bits = bytesToBinary(Array.from(entropy));
    const chunks = bits.slice(0, 104).match(/(.{1,13})/g);
    const words = chunks.map((binary) => {
        const index = binaryToByte(binary);
        const word = wordlist[index];
        return word;
    });
    const chunks2 = bits.slice(104).match(/(.{1,3})/g);
    const digits = chunks2.map((binary) => {
        return bitsToDigit(binary);
    });
    const zipped = words.map((item1, index) => item1 + digits[index]);
    return zipped.join(' ');
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
        DEFAULT_WORDLIST_8192 = _wordlists_1.wordlists['EN8192'];
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
function convertLegacyToCompressed(mnemonic, wordlistLegacy, wordlist8192) {
    wordlistLegacy = wordlistLegacy || DEFAULT_WORDLIST;
    wordlist8192 = wordlist8192 || DEFAULT_WORDLIST_8192;
    if (!wordlistLegacy || !wordlist8192) {
        throw new Error(WORDLIST_REQUIRED);
    }
    const legacyWords = normalize(mnemonic).split(' ');
    if (legacyWords.length !== 12) {
        throw new Error('only 12 word legacy mnemonics are supported for conversion');
    }
    const entropy = legacyMnemonicToEntropy(mnemonic, wordlistLegacy);
    return entropyToMnemonic(entropy, wordlist8192);
}
exports.convertLegacyToCompressed = convertLegacyToCompressed;
function convertCompressedToLegacy(mnemonic, wordlistLegacy, wordlist8192) {
    wordlistLegacy = wordlistLegacy || DEFAULT_WORDLIST;
    wordlist8192 = wordlist8192 || DEFAULT_WORDLIST_8192;
    if (!wordlistLegacy || !wordlist8192) {
        throw new Error(WORDLIST_REQUIRED);
    }
    const compressedWords = normalize(mnemonic).split(' ');
    if (compressedWords.length !== 8) {
        throw new Error('Compressed mneomonics must be length 8');
    }
    const entropy = mnemonicToEntropy(mnemonic, wordlist8192);
    return entropyToLegacyMnemonic(entropy, wordlistLegacy);
}
exports.convertCompressedToLegacy = convertCompressedToLegacy;
function entropyToLegacyMnemonic(entropy, wordlist) {
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
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map((binary) => {
        const index = binaryToByte(binary);
        return wordlist[index];
    });
    return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
        ? words.join('\u3000')
        : words.join(' ');
}
exports.entropyToLegacyMnemonic = entropyToLegacyMnemonic;
function legacyMnemonicToEntropy(mnemonic, wordlist) {
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
        .map((word) => {
        const index = wordlist.indexOf(word);
        if (index === -1) {
            throw new Error(INVALID_MNEMONIC);
        }
        return lpad(index.toString(2), '0', 11);
    })
        .join('');
    // split the binary string into ENT/CS
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropyBits = bits.slice(0, dividerIndex);
    const checksumBits = bits.slice(dividerIndex);
    // calculate the checksum and compare
    const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
    if (entropyBytes.length !== 16) {
        throw new Error(INVALID_ENTROPY);
    }
    const entropy = Buffer.from(entropyBytes);
    const newChecksum = deriveChecksumBits(entropy);
    if (newChecksum !== checksumBits) {
        throw new Error(INVALID_CHECKSUM);
    }
    return entropy.toString('hex');
}
exports.legacyMnemonicToEntropy = legacyMnemonicToEntropy;
var _wordlists_2 = require("./_wordlists");
exports.wordlists = _wordlists_2.wordlists;
