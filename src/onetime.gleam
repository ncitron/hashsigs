import gleam/crypto.{Sha256}
import gleam/iterator
import gleam/list

pub type SecretKey {
  SecretKey(bit_keys: List(#(BitArray, BitArray)))
}

pub type PublicKey {
  PublicKey(bit_keys: List(#(BitArray, BitArray)))
}

pub type Signature {
  Signature(secrets: List(BitArray))
}

pub fn rand_secret_key() -> SecretKey {
  let bit_keys =
    iterator.range(0, 255)
    |> iterator.map(fn(_) {
      let zero = crypto.strong_random_bytes(32)
      let one = crypto.strong_random_bytes(32)
      #(zero, one)
    })
    |> iterator.to_list

  SecretKey(bit_keys)
}

pub fn to_public_key(sk: SecretKey) -> PublicKey {
  let bit_keys =
    sk.bit_keys
    |> list.map(fn(elem) {
      let zero = crypto.hash(Sha256, elem.0)
      let one = crypto.hash(Sha256, elem.1)
      #(zero, one)
    })

  PublicKey(bit_keys)
}

pub fn sign(sk: SecretKey, msg: BitArray) -> Signature {
  crypto.hash(Sha256, msg)
  |> bits_to_list
  |> list.zip(sk.bit_keys)
  |> list.map(fn(inputs) {
    let #(bit, key) = inputs
    case bit {
      False -> key.0
      True -> key.1
    }
  })
  |> Signature
}

pub fn verify(pk: PublicKey, sig: Signature, msg: BitArray) -> Bool {
  crypto.hash(Sha256, msg)
  |> bits_to_list
  |> list.zip(pk.bit_keys)
  |> list.zip(sig.secrets)
  |> list.map(fn(inputs) {
    let #(#(bit, pk_hashes), sk_secret) = inputs
    let expected_hash = case bit {
      False -> pk_hashes.0
      True -> pk_hashes.1
    }

    let hash = crypto.hash(Sha256, sk_secret)
    hash == expected_hash
  })
  |> list.all(fn(b) { b })
}

fn bits_to_list(bits: BitArray) -> List(Bool) {
  case bits {
    <<bit:size(1), rest:bits>> -> [bit == 1, ..bits_to_list(rest)]
    _ -> []
  }
}
