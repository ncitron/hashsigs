import gleam/bit_array
import gleeunit/should
import winternitz

pub fn verify_success_test() {
  let sk = winternitz.rand_secret_key()
  let pk = winternitz.to_public_key(sk)

  let msg = bit_array.from_string("hello")
  let sig = winternitz.sign(sk, msg)
  let is_valid = winternitz.verify(pk, sig, msg)

  is_valid
  |> should.be_true
}

pub fn verify_fail_bad_key_test() {
  let sk = winternitz.rand_secret_key()
  let msg = bit_array.from_string("hello")
  let sig = winternitz.sign(sk, msg)

  let other_sk = winternitz.rand_secret_key()
  let other_pk = winternitz.to_public_key(other_sk)
  let is_valid = winternitz.verify(other_pk, sig, msg)

  is_valid
  |> should.be_false
}

pub fn verify_fail_bad_msg_test() {
  let sk = winternitz.rand_secret_key()
  let pk = winternitz.to_public_key(sk)

  let msg = bit_array.from_string("hello")
  let sig = winternitz.sign(sk, msg)

  let other_msg = bit_array.from_string("goodbye")
  let is_valid = winternitz.verify(pk, sig, other_msg)

  is_valid
  |> should.be_false
}
