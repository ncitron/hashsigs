import gleam/bit_array
import gleeunit/should
import onetime

pub fn verify_success_test() {
  let sk = onetime.rand_secret_key()
  let pk = onetime.to_public_key(sk)

  let msg = bit_array.from_string("hello")
  let sig = onetime.sign(sk, msg)
  let is_valid = onetime.verify(pk, sig, msg)

  is_valid
  |> should.be_true
}

pub fn verify_fail_bad_key_test() {
  let sk = onetime.rand_secret_key()
  let msg = bit_array.from_string("hello")
  let sig = onetime.sign(sk, msg)

  let other_sk = onetime.rand_secret_key()
  let other_pk = onetime.to_public_key(other_sk)
  let is_valid = onetime.verify(other_pk, sig, msg)

  is_valid
  |> should.be_false
}

pub fn verify_fail_bad_msg_test() {
  let sk = onetime.rand_secret_key()
  let pk = onetime.to_public_key(sk)

  let msg = bit_array.from_string("hello")
  let sig = onetime.sign(sk, msg)

  let other_msg = bit_array.from_string("goodbye")
  let is_valid = onetime.verify(pk, sig, other_msg)

  is_valid
  |> should.be_false
}
