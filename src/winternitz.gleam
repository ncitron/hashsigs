import gleam/bytes_builder
import gleam/crypto.{Sha256}
import gleam/float
import gleam/int
import gleam/iterator
import gleam/list
import gleam/option.{Some}
import gleam_community/maths/elementary

const d = 1023

const n = 28

pub type SecretKey {
  SecretKey(keys: List(BitArray))
}

pub type PublicKey {
  PublicKey(key: BitArray)
}

pub type Signature {
  Signature(values: List(BitArray))
}

pub fn rand_secret_key() -> SecretKey {
  iterator.range(1, n)
  |> iterator.map(fn(_) { crypto.strong_random_bytes(32) })
  |> iterator.to_list
  |> SecretKey
}

pub fn to_public_key(sk: SecretKey) -> PublicKey {
  sk.keys
  |> list.map(fn(x) { hash_chain(x, d) })
  |> list.fold(bytes_builder.new(), bytes_builder.append)
  |> bytes_builder.to_bit_array
  |> fn(value) { crypto.hash(Sha256, value) }
  |> PublicKey
}

pub fn sign(sk: SecretKey, msg: BitArray) -> Signature {
  msg
  |> msg_to_int
  |> p(d)
  |> list.zip(sk.keys)
  |> list.map(fn(input) {
    let #(s, x) = input
    hash_chain(x, s)
  })
  |> Signature
}

pub fn verify(pk: PublicKey, sig: Signature, msg: BitArray) -> Bool {
  let expected_pk =
    msg
    |> msg_to_int
    |> p(d)
    |> list.zip(sig.values)
    |> list.map(fn(input) {
      let #(s, sig) = input
      hash_chain(sig, d - s)
    })
    |> list.fold(bytes_builder.new(), bytes_builder.append)
    |> bytes_builder.to_bit_array
    |> fn(value) { crypto.hash(Sha256, value) }

  expected_pk == pk.key
}

fn msg_to_int(msg: BitArray) -> Int {
  let msg_hash = crypto.hash(Sha256, msg)
  case msg_hash {
    <<val:size(256)>> -> val
    _ -> panic as "unreachable"
  }
}

fn hash_chain(input: BitArray, iters: Int) -> BitArray {
  case iters {
    0 -> input
    _ -> hash_chain(crypto.hash(Sha256, input), iters - 1)
  }
}

fn p(m: Int, d: Int) -> List(Int) {
  // interpret m as a base d+1 number
  let assert Ok(s) = int.digits(m, d + 1)
  let len = list.length(s)
  let n0 = n0(d)
  let start = list.repeat(0, n0 - len)
  let s = list.append(start, s)

  // calculate checksum
  let c = d * n0 - list.fold(s, 0, int.add)

  // interpret checksum as base d+1 number
  let assert Ok(c) = int.digits(c, d + 1)
  let len = list.length(s)
  let n1 = n1(n0, d)
  let start = list.repeat(0, n1 - len)
  let c = list.append(start, c)

  // concatenate s and c
  list.append(s, c)
}

pub fn n0(d: Int) -> Int {
  let assert Ok(max) = float.power(2.0, 256.0)
  let base = int.to_float(d) +. 1.0
  let assert Ok(log) = elementary.logarithm(max, Some(base))
  log
  |> float.ceiling
  |> float.round
}

pub fn n1(n0: Int, d: Int) -> Int {
  let base = int.to_float(d) +. 1.0
  let val = int.to_float(d * n0)
  let assert Ok(log) = elementary.logarithm(val, Some(base))
  log
  |> float.ceiling
  |> float.round
  |> int.add(1)
}
