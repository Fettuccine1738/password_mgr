// use pass_man::{self};

// pub mod lib_test {

//     fn tests_lib_creation_is_succesful() {

//     }
// }

// pub mod encryption_test {

// }

#[cfg(test)]
pub mod vc_test {
    use pass_man::data_struct::Secret;
    use pass_man::data_struct::vc::VaultContents;
    use pass_man::utils::DECRYPTION_CHECK_TAG;

    const A: &str = "https://claude.ai/";
    const B: &str = "Mike";
    const C: &str = "pass1";

    const D: &str = "https://gmail.ai/";
    const E: &str = "Mike@gmail.com";
    const F: &str = "passw";
    const G: &str = "my student mail";

    fn helper_get_serialized_secrets() -> VaultContents {
        let secret1: Secret = Secret::new(A.to_owned(), B.to_owned(), C.to_owned(), None);
        let secret2: Secret =
            Secret::new(D.to_owned(), E.to_owned(), F.to_owned(), Some(G.to_owned()));

        let vc: VaultContents = VaultContents {
            secrets: vec![secret1, secret2],
        };

        vc
    }

    #[test]
    fn test_serialize_success() {
        let expected_len = DECRYPTION_CHECK_TAG.len()
            + A.bytes().len()
            + B.bytes().len()
            + C.bytes().len()
            + D.bytes().len()
            + E.bytes().len()
            + F.bytes().len()
            + G.bytes().len();
        let ctnt: Vec<u8> = helper_get_serialized_secrets().serialize();
        assert!(ctnt.len() > expected_len); // ctnt adds the length of valid fields before serializing the field's value 
    }

    #[test]
    fn test_deser_success_on_well_formed() {
        let vc = helper_get_serialized_secrets();
        let ctnt = vc.serialize();
        let ds = VaultContents::deserialize(&ctnt);
        assert!(ds.is_ok());
        assert_eq!(vc, ds.unwrap());
    }

    #[test]
    fn test_deser_fails_on_malformed_data() {
        let ctnt: Vec<u8> = vec![1, 2, 3, 4];
        let ds = VaultContents::deserialize(&ctnt);
        assert!(ds.is_err());
    }
}
