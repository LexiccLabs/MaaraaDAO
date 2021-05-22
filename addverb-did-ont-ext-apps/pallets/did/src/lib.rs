#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::{format, str, string::*};
use codec::{Decode, Encode};
/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use sp_std::vec::Vec;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Config: frame_system::Config + pallet_timestamp::Config {
    /// Because this pallet emits events, it depends on the runtime's definition of an event.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
}

const VALID: u8 = 0;
const DEACTIVE: u8 = 1;

#[derive(Encode, Decode, Default)]
pub struct PkList<A> {
    pk_list: Vec<Pk<A>>,
}

impl<A: core::cmp::Eq> PkList<A> {
    pub fn new_default(controller: Vec<u8>, acc: A) -> Self {
        let mut l = Vec::new();
        l.push(Pk::new_acc_and_auth(controller, acc));
        PkList { pk_list: l }
    }

    pub fn contains(&self, acc: &A) -> bool {
        for v in self.pk_list.iter() {
            if &v.public_key == acc {
                return true;
            }
        }
        return false;
    }

    pub fn have_access(&self, acc: &A) -> bool {
        for v in self.pk_list.iter() {
            if &v.public_key == acc {
                if v.deactivated == false && v.is_authentication == true {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn push(&mut self, account_id: Pk<A>) {
        self.pk_list.push(account_id);
    }

    pub fn deactivate_acc(&mut self, acc: &A) {
        for v in self.pk_list.iter_mut() {
            if &v.public_key == acc {
                v.deactivated = true;
                return;
            }
        }
        return;
    }

    pub fn set_acc_auth(&mut self, acc: &A) {
        for v in self.pk_list.iter_mut() {
            if &v.public_key == acc {
                v.is_authentication = true;
                return;
            }
        }
        return;
    }

    pub fn remove_acc_auth(&mut self, acc: &A) {
        for v in self.pk_list.iter_mut() {
            if &v.public_key == acc {
                v.is_authentication = false;
                return;
            }
        }
        return;
    }

    pub fn find_acc(&self, acc: &A) -> Option<u32> {
        for (index, v) in self.pk_list.iter().enumerate() {
            if &v.public_key == acc {
                return Some(index as u32);
            }
        }
        return None;
    }

    pub fn len(&self) -> u32 {
        self.pk_list.len() as u32
    }
}

impl<A: core::convert::AsRef<[u8]> + core::cmp::Eq> PkList<A> {
    pub fn to_json(&self, did: &Vec<u8>) -> Vec<PkJson> {
        let mut result = Vec::new();
        for (i, v) in self.pk_list.iter().enumerate() {
            if !v.is_pk_list {
                continue;
            }
            let tp: String = "".to_string();
            //            match v.public_key[0] {
            //                0 => tp = KeyType::Ed25519VerificationKey2018.to_string(),
            //                1 => tp = KeyType::EcdsaSecp256k1VerificationKey2019.to_string(),
            //                _ => {}
            //            }
            let pk_json = PkJson {
                id: format!("{}#keys-{}", str::from_utf8(did).ok().unwrap(), i + 1),
                tp,
                controller: str::from_utf8(&v.controller).ok().unwrap().to_string(),
                public_key_hex: format!("{:x?}", v.public_key.as_ref()),
            };
            result.push(pk_json);
        }
        result
    }

    pub fn to_authentication_json(
        &self,
        did: &Vec<u8>,
        authentication_list: Vec<u32>,
    ) -> Vec<AuthenticationJson> {
        let mut result = Vec::new();
        for i in authentication_list.iter() {
            let public_key: &Pk<A> = self.pk_list.get(*i as usize).unwrap();
            if public_key.is_pk_list {
                let authentication = AuthenticationJson::Pk(format!(
                    "{}#keys-{}",
                    str::from_utf8(did).ok().unwrap(),
                    i + 1
                ));
                result.push(authentication);
            } else {
                let tp: String = "".to_string();
                //                match public_key.public_key[0] {
                //                    0 => tp = KeyType::Ed25519VerificationKey2018.to_string(),
                //                    1 => tp = KeyType::EcdsaSecp256k1VerificationKey2019.to_string(),
                //                    _ => {}
                //                }
                let authentication = AuthenticationJson::NotPK(PkJson {
                    id: format!("{}#keys-{}", str::from_utf8(did).ok().unwrap(), i + 1),
                    tp,
                    controller: str::from_utf8(&public_key.controller)
                        .ok()
                        .unwrap()
                        .to_string(),
                    public_key_hex: format!("{:x?}", public_key.public_key.as_ref()),
                });
                result.push(authentication);
            }
        }
        result
    }
}

#[derive(Encode, Decode, Default)]
pub struct Pk<A> {
    controller: Vec<u8>,
    public_key: A,
    deactivated: bool,
    is_pk_list: bool,
    is_authentication: bool,
}

impl<A> Pk<A> {
    pub fn new_acc_and_auth(controller: Vec<u8>, acc: A) -> Self {
        Pk {
            controller,
            public_key: acc,
            deactivated: false,
            is_pk_list: true,
            is_authentication: true,
        }
    }

    pub fn new_acc(controller: Vec<u8>, acc: A) -> Self {
        Pk {
            controller,
            public_key: acc,
            deactivated: false,
            is_pk_list: true,
            is_authentication: false,
        }
    }

    pub fn new_auth(controller: Vec<u8>, acc: A) -> Self {
        Pk {
            controller,
            public_key: acc,
            deactivated: false,
            is_pk_list: false,
            is_authentication: true,
        }
    }
}

#[derive(Encode, Decode, Default)]
pub struct Service {
    id: Vec<u8>,
    tp: Vec<u8>,
    service_endpoint: Vec<u8>,
}

impl Service {
    pub fn to_json(&self) -> ServiceJson {
        ServiceJson {
            id: str::from_utf8(&self.id).ok().unwrap().to_string(),
            tp: str::from_utf8(&self.tp).ok().unwrap().to_string(),
            service_endpoint: str::from_utf8(&self.service_endpoint)
                .ok()
                .unwrap()
                .to_string(),
        }
    }
}

pub struct PkJson {
    id: String,
    tp: String,
    controller: String,
    public_key_hex: String,
}

pub struct ServiceJson {
    id: String,
    tp: String,
    service_endpoint: String,
}

pub enum AuthenticationJson {
    Pk(String),
    NotPK(PkJson),
}

pub struct Document<A> {
    pub contexts: Vec<String>,
    pub id: String,
    pub public_key: Vec<PkJson>,
    pub authentication: Vec<AuthenticationJson>,
    pub controller: Vec<String>,
    pub service: Vec<ServiceJson>,
    pub created: A,
    pub updated: A,
}

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
    // A unique name is used to ensure that the pallet's storage items are isolated.
    // This name may be updated, but each pallet in the runtime must use a unique name.
    // ---------------------------------vvvvvvvvvvvvvv
    trait Store for Module<T: Config> as DID {
        // Learn more about declaring storage items:
        // https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
        pub StatusStore: map hasher(blake2_128_concat) Vec<u8> => u8;

        pub ContextStore: map hasher(blake2_128_concat) Vec<u8> => Vec<Vec<u8>> = Vec::new();

        pub PkListStore: map hasher(blake2_128_concat) Vec<u8> => PkList<T::AccountId>;

        pub AuthenticationStore: map hasher(blake2_128_concat) Vec<u8> => Vec<u32> = Vec::new();

        pub ControllerStore: map hasher(blake2_128_concat) Vec<u8> => Vec<Vec<u8>> = Vec::new();

        pub ServiceStore: map hasher(blake2_128_concat) Vec<u8> => Vec<Service> = Vec::new();

        pub CreatedStore: map hasher(blake2_128_concat) Vec<u8> => T::Moment;

        pub UpdatedStore: map hasher(blake2_128_concat) Vec<u8> => T::Moment;
    }
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as frame_system::Config>::AccountId,
    {
        /// Event documentation should end with an array that provides descriptive names for event
        /// parameters.
        RegisterWithAccount(Vec<u8>, AccountId),
        DeactivateDid(Vec<u8>),
        AddController(Vec<u8>, Vec<u8>),
        RemoveController(Vec<u8>, Vec<u8>),
        AddKey(Vec<u8>, AccountId, Vec<u8>),
        DeactivateKey(Vec<u8>, AccountId),
        AddNewAuthKey(Vec<u8>, AccountId, Vec<u8>),
        SetAuthKey(Vec<u8>, AccountId),
        DeactivateAuthKey(Vec<u8>, AccountId),
        AddNewAuthKeyByController(Vec<u8>, AccountId, Vec<u8>),
        SetAuthKeyByController(Vec<u8>, AccountId),
        DeactivateAuthKeyByController(Vec<u8>, AccountId),
        AddService(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
        UpdateService(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
        RemoveService(Vec<u8>, Vec<u8>),
        AddContext(Vec<u8>, Vec<u8>),
        RemoveContext(Vec<u8>, Vec<u8>),
        VerifySignature(Vec<u8>),
        VerifyController(Vec<u8>, Vec<u8>),
    }
);

// Errors inform users that something went wrong.
decl_error! {
    pub enum Error for Module<T: Config> {
        /// Error names should be descriptive.
        AlreadyRegistered,
        /// Errors should have helpful documentation associated with them.
        NotRegistered,
        Invalid,
        NoAccess,
        ControllerExist,
        ControllerNotExist,
        AccountIdExist,
        AccountIdNotExist,
        AccountIdDeactivated,
        ServiceExist,
        ServiceNotExist,
        ContextExist,
        ContextNotExist,
    }
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        // Errors must be initialized if they are used by the pallet.
        type Error = Error<T>;

        // Events must be initialized if they are used by the pallet.
        fn deposit_event() = default;

        /// An example dispatchable that takes a singles value as a parameter, writes the value to
        /// storage and emits an event. This function must be dispatched by a signed extrinsic.
        #[weight = 0]
        pub fn reg_did_using_account(origin, did: Vec<u8>) -> dispatch::DispatchResult {
            // Check that the extrinsic was signed and get the signer.
            // This function will return an error if the extrinsic is not signed.
            // https://substrate.dev/docs/en/knowledgebase/runtime/origin
            let sender = ensure_signed(origin)?;

            // Verify that the specified accountId has not already been registered.
            ensure!(!StatusStore::contains_key(&did), Error::<T>::AlreadyRegistered);
            // Update storage.
            StatusStore::insert(&did, VALID);
            <PkListStore<T>>::insert(&did, PkList::<T::AccountId>::new_default(did.clone(), sender.clone()));
            let mut a = Vec::new();
            a.push(0);
            AuthenticationStore::insert(&did, a);
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <CreatedStore<T>>::insert(&did, now_timestamp);

            // Emit an event.
            Self::deposit_event(RawEvent::RegisterWithAccount(did, sender));
            // Return a successful DispatchResult
            Ok(())
        }

        #[weight = 0]
        pub fn deactivate_did(origin, did: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            // Update storage.
            StatusStore::insert(&did, DEACTIVE);
            ContextStore::remove(&did);
            <PkListStore<T>>::remove(&did);
            AuthenticationStore::remove(&did);
            ControllerStore::remove(&did);
            ServiceStore::remove(&did);
            <CreatedStore<T>>::remove(&did);
            <UpdatedStore<T>>::remove(&did);

            Self::deposit_event(RawEvent::DeactivateDid(did));
            Ok(())
        }

        #[weight = 0]
        pub fn add_controller(origin, did: Vec<u8>, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let controller_list = ControllerStore::get(&did);
            ensure!(!controller_list.contains(&controller), Error::<T>::ControllerExist);
            ControllerStore::mutate(&did, |c| c.push(controller.clone()));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::AddController(did, controller));
            Ok(())
        }

        #[weight = 0]
        pub fn remove_controller(origin, did: Vec<u8>, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let controller_list = ControllerStore::get(&did);
            ensure!(controller_list.contains(&controller), Error::<T>::ControllerNotExist);
            let index = controller_list
            .iter()
            .position(|x| x == &controller)
            .unwrap();
            ControllerStore::mutate(&did, |c| c.remove(index));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::RemoveController(did, controller));
            Ok(())
        }

        #[weight = 0]
        pub fn add_key(origin, did: Vec<u8>, key: T::AccountId, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            ensure!(!account_id_list.contains(&key), Error::<T>::AccountIdExist);
            <PkListStore<T>>::mutate(&did, |c| c.push(Pk::<T::AccountId>::new_acc(controller.clone(), key.clone())));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::AddKey(did, key, controller));
            Ok(())
        }

        #[weight = 0]
        pub fn deactivate_key(origin, did: Vec<u8>, key: T::AccountId) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            ensure!(account_id_list.contains(&key), Error::<T>::AccountIdNotExist);
            <PkListStore<T>>::mutate(&did, |c| c.deactivate_acc(&key));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::DeactivateKey(did, key));
            Ok(())
        }

        #[weight = 0]
        pub fn add_new_auth_key(origin, did: Vec<u8>, key: T::AccountId, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            ensure!(!account_id_list.contains(&key), Error::<T>::AccountIdExist);
            <PkListStore<T>>::mutate(&did, |c| c.push(Pk::<T::AccountId>::new_acc(controller.clone(), key.clone())));
            let index: u32 = (account_id_list.len() - 1) as u32;
            AuthenticationStore::mutate(&did, |c| c.push(index));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::AddNewAuthKey(did, key, controller));
            Ok(())
        }

        #[weight = 0]
        pub fn set_auth_key(origin, did: Vec<u8>, key: T::AccountId) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            let index = account_id_list.find_acc(&key);
            ensure!(index.is_some(), Error::<T>::AccountIdNotExist);
            <PkListStore<T>>::mutate(&did, |c| c.set_acc_auth(&key));
            AuthenticationStore::mutate(&did, |c| c.push(index.unwrap()));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::SetAuthKey(did, key));
            Ok(())
        }

        #[weight = 0]
        pub fn deactivate_auth_key(origin, did: Vec<u8>, key: T::AccountId) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            let authentication_list = AuthenticationStore::get(&did);
            let index = account_id_list.find_acc(&key);
            ensure!(index.is_some(), Error::<T>::AccountIdNotExist);
            <PkListStore<T>>::mutate(&did, |c| c.remove_acc_auth(&key));
            let i = authentication_list
            .iter()
            .position(|x| x == &(index.unwrap() as u32))
            .unwrap();
            AuthenticationStore::mutate(&did, |c| c.remove(i));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::DeactivateAuthKey(did, key));
            Ok(())
        }

        #[weight = 0]
        pub fn add_new_auth_key_by_controller(origin, did: Vec<u8>, key: T::AccountId, pk_controller: Vec<u8>, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            let controller_list = ControllerStore::get(&did);
            ensure!(controller_list.contains(&controller), Error::<T>::ControllerNotExist);
            Self::check_access(&controller, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            ensure!(!account_id_list.have_access(&key), Error::<T>::AccountIdExist);
            <PkListStore<T>>::mutate(&did, |c| c.push(Pk::<T::AccountId>::new_acc(controller.clone(), key.clone())));
            let index: u32 = (account_id_list.len() - 1) as u32;
            AuthenticationStore::mutate(&did, |c| c.push(index));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::AddNewAuthKeyByController(did, key, controller));
            Ok(())
        }

        #[weight = 0]
        pub fn set_auth_key_by_controller(origin, did: Vec<u8>, key: T::AccountId, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            let controller_list = ControllerStore::get(&did);
            ensure!(controller_list.contains(&controller), Error::<T>::ControllerNotExist);
            Self::check_access(&controller, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            let index = account_id_list.find_acc(&key);
            ensure!(index.is_some(), Error::<T>::AccountIdNotExist);
            <PkListStore<T>>::mutate(&did, |c| c.set_acc_auth(&key));
            AuthenticationStore::mutate(&did, |c| c.push(index.unwrap()));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::SetAuthKeyByController(did, key));
            Ok(())
        }

        #[weight = 0]
        pub fn deactivate_auth_key_by_controller(origin, did: Vec<u8>, key: T::AccountId, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            let controller_list = ControllerStore::get(&did);
            ensure!(controller_list.contains(&controller), Error::<T>::ControllerNotExist);
            Self::check_access(&controller, &sender)?;

            let account_id_list = <PkListStore<T>>::get(&did);
            let authentication_list = AuthenticationStore::get(&did);
            let index = account_id_list.find_acc(&key);
            ensure!(index.is_some(), Error::<T>::AccountIdNotExist);
            <PkListStore<T>>::mutate(&did, |c| c.remove_acc_auth(&key));
            let i = authentication_list
            .iter()
            .position(|x| x == &(index.unwrap() as u32))
            .unwrap();
            AuthenticationStore::mutate(&did, |c| c.remove(i));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::DeactivateAuthKeyByController(did, key));
            Ok(())
        }

        #[weight = 0]
        pub fn add_service(origin, did: Vec<u8>, service_id: Vec<u8>, service_type: Vec<u8>, endpoint: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let ser = Service {
                id: service_id.clone(),
                tp: service_type.clone(),
                service_endpoint: endpoint.clone(),
            };
            let service_list = ServiceStore::get(&did);
            let index = service_list.iter().position(|x| &x.id == &ser.id);
            ensure!(index.is_none(), Error::<T>::ServiceExist);
            ServiceStore::mutate(&did, |c| c.push(ser));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::AddService(did, service_id, service_type, endpoint));
            Ok(())
        }

        #[weight = 0]
        pub fn update_service(origin, did: Vec<u8>, service_id: Vec<u8>, service_type: Vec<u8>, endpoint: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let service_list = ServiceStore::get(&did);
            let index = service_list.iter().position(|x| &x.id == &service_id);
            ensure!(index.is_some(), Error::<T>::ServiceNotExist);
            ServiceStore::mutate(&did, |c| {
                let ser = c.get_mut(index.unwrap()).unwrap();
                ser.id = service_id.clone();
                ser.tp = service_type.clone();
                ser.service_endpoint = endpoint.clone();
            });
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::UpdateService(did, service_id, service_type, endpoint));
            Ok(())
        }

        #[weight = 0]
        pub fn remove_service(origin, did: Vec<u8>, service_id: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let service_list = ServiceStore::get(&did);
            let index = service_list.iter().position(|x| &x.id == &service_id);
            ensure!(index.is_some(), Error::<T>::ServiceNotExist);
            ServiceStore::mutate(&did, |c| c.remove(index.unwrap()));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::RemoveService(did, service_id));
            Ok(())
        }

        #[weight = 0]
        pub fn add_context(origin, did: Vec<u8>, context: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let context_list = ContextStore::get(&did);
            ensure!(!context_list.contains(&context), Error::<T>::ContextExist);
            ContextStore::mutate(&did, |c| c.push(context.clone()));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::AddContext(did, context));
            Ok(())
        }

        #[weight = 0]
        pub fn remove_context(origin, did: Vec<u8>, context: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            let context_list = ContextStore::get(&did);
            ensure!(context_list.contains(&context), Error::<T>::ContextNotExist);
            let index = context_list.iter().position(|x| *x == context);
            ContextStore::mutate(&did, |c| c.remove(index.unwrap()));
            let now_timestamp = <pallet_timestamp::Module<T>>::now();
            <UpdatedStore<T>>::mutate(&did, |c| *c = now_timestamp);

            Self::deposit_event(RawEvent::RemoveContext(did, context));
            Ok(())
        }

        #[weight = 0]
        pub fn verify_signature(origin, did: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            Self::check_access(&did, &sender)?;

            Self::deposit_event(RawEvent::VerifySignature(did));
            Ok(())
        }

        #[weight = 0]
        pub fn verify_controller(origin, did: Vec<u8>, controller: Vec<u8>) -> dispatch::DispatchResult {
            let sender = ensure_signed(origin)?;
            Self::check_did_status(&did)?;
            let controller_list = ControllerStore::get(&did);
            ensure!(controller_list.contains(&controller), Error::<T>::ControllerNotExist);
            Self::check_access(&controller, &sender)?;

            Self::deposit_event(RawEvent::VerifyController(did, controller));
            Ok(())
        }
    }
}

impl<T: Config> Module<T> {
    pub fn check_did_status(did: &Vec<u8>) -> dispatch::DispatchResult {
        ensure!(StatusStore::contains_key(did), Error::<T>::NotRegistered);
        if StatusStore::get(did) != VALID {
            Err(Error::<T>::Invalid.into())
        } else {
            Ok(())
        }
    }

    pub fn check_access(did: &Vec<u8>, caller: &T::AccountId) -> dispatch::DispatchResult {
        let pk_list = <PkListStore<T>>::get(did);
        ensure!(pk_list.have_access(caller), Error::<T>::NoAccess);
        Ok(())
    }
}

impl<T> Module<T>
where
    T: Config,
    <T as frame_system::Config>::AccountId: core::convert::AsRef<[u8]> {
    pub fn get_document(did: Vec<u8>) -> Option<Document<T::Moment>> {
        let id = str::from_utf8(&did).ok().unwrap();
        let pk_list = <PkListStore<T>>::get(&did);
        let pk_list_json = pk_list.to_json(&did);
        let authentication_list = AuthenticationStore::get(&did);
        let authentication_json = pk_list.to_authentication_json(&did, authentication_list);
        let context_list = ContextStore::get(&did);
        let mut contexts_json = Vec::new();
        for v in context_list.iter() {
            let s = str::from_utf8(&v).ok().unwrap().to_string();
            contexts_json.push(s);
        }
        let controller_list = ControllerStore::get(&did);
        let mut controller_json = Vec::new();
        for v in controller_list.iter() {
            let s = str::from_utf8(&v).ok().unwrap().to_string();
            controller_json.push(s);
        }
        let service_list = ServiceStore::get(&did);
        let mut service_json = Vec::new();
        for v in service_list.iter() {
            service_json.push(v.to_json());
        }
        let created = <CreatedStore<T>>::get(&did);
        let updated = <UpdatedStore<T>>::get(&did);
        let document = Document {
            id: id.to_string(),
            public_key: pk_list_json,
            authentication: authentication_json,
            contexts: contexts_json,
            controller: controller_json,
            service: service_json,
            created,
            updated,
        };
        Some(document)
    }
}
