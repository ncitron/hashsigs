import gleam/bit_array
import gleeunit/should
import lamport

pub fn verify_success_test() {
  let sk = lamport.rand_secret_key()
  let pk = lamport.to_public_key(sk)

  let msg = bit_array.from_string("hello")
  let sig = lamport.sign(sk, msg)
  let is_valid = lamport.verify(pk, sig, msg)

  is_valid
  |> should.be_true
}

pub fn verify_fail_bad_key_test() {
  let sk = lamport.rand_secret_key()
  let msg = bit_array.from_string("hello")
  let sig = lamport.sign(sk, msg)

  let other_sk = lamport.rand_secret_key()
  let other_pk = lamport.to_public_key(other_sk)
  let is_valid = lamport.verify(other_pk, sig, msg)

  is_valid
  |> should.be_false
}

pub fn verify_fail_bad_msg_test() {
  let sk = lamport.rand_secret_key()
  let pk = lamport.to_public_key(sk)

  let msg = bit_array.from_string("hello")
  let sig = lamport.sign(sk, msg)

  let other_msg = bit_array.from_string("goodbye")
  let is_valid = lamport.verify(pk, sig, other_msg)

  is_valid
  |> should.be_false
}
