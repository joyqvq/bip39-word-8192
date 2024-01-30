const bip39 = require('../')
const Buffer = require('safe-buffer').Buffer
const proxyquire = require('proxyquire')
const test = require('tape')

test('README example 1', function (t) {
  // defaults to BIP39 English word list
  const entropy = 'ffffffffffffffffffffffffffffffff'
  const legacymnemonic = bip39.entropyToLegacyMnemonic(entropy)
  const mnemonic = bip39.entropyToMnemonic(entropy)

  t.plan(4)
  t.equal(legacymnemonic, 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong')
  t.equal(mnemonic, '8192word-7 8192word-7 8192word-7 8192word-7 8192word-7 8192word-7 8192word-7 8192word-7')

  // reversible
  t.equal(bip39.mnemonicToEntropy(mnemonic), entropy)
  t.equal(bip39.legacyMnemonicToEntropy(legacymnemonic), entropy)
})

test('README example 2', function (t) {
  const stub = {
    '@noble/hashes/utils': {
      randomBytes: function (size) {
        return Uint8Array.from(Buffer.from('qwertyuiopasdfghjklzxcvbnm[];,./'.slice(0, size), 'utf8'))
      }
    }
  }
  const proxiedbip39 = proxyquire('../', stub)

  // mnemonic strength defaults to 128 bits
  const mnemonic = proxiedbip39.generateMnemonic()
  const legacyMnemonic = bip39.convertCompressedToLegacy(mnemonic)
  t.plan(2)
  t.equal(legacyMnemonic, 'imitate robot frame trophy nuclear regret saddle around inflict case oil spice')
  t.equal(bip39.validateMnemonic(mnemonic), true)
})

test('README example 3', function (t) {
  const mnemonic = '1word-0 1word-0 1word-0 1word-0 1word-0 1word-0 1word-0 1word-0'
  const badmnemonic = 'bad-0 1word-0 1word-0 1word-0 1word-0 1word-0 1word-0 1word-0'
  const seed = bip39.mnemonicToSeedSync(mnemonic)

  t.plan(3)
  t.equal(seed.toString('hex'), '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
  t.equal(bip39.validateMnemonic(mnemonic), true)
  t.equal(bip39.validateMnemonic(badmnemonic), false)
})
