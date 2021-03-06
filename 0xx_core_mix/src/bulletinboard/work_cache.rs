use std::io::Result;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use crate::bulletinboard::*;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::crypto::elgamal::PublicKey;
use crate::crypto::hashing;
use crate::data::artifact::*;
use crate::data::bytes::*;
use crate::protocol::facts::Act;
use crate::protocol::statement::*;
use crate::util;

pub struct WorkCache<E, G> {
    pub fs_path: PathBuf,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>,
}

impl<E: Element, G: Group<E>> WorkCache<E, G> {
    pub fn new(fs_path: String) -> WorkCache<E, G> {
        let target = Path::new(&fs_path);
        assert!(target.exists() && target.is_dir());
        WorkCache {
            fs_path: target.to_path_buf(),
            phantom_e: PhantomData,
            phantom_g: PhantomData,
        }
    }
    pub fn set_config_stmt(&self, act: &Act, stmt: &SignedStatement) -> Result<ConfigStmtPath> {
        assert!(matches!(act, Act::CheckConfig(_)));
        assert!(matches!(stmt.statement.stype, StatementType::Config));
        let stmt_b = stmt.ser();
        let stmt_p = self.set_work(act, vec![stmt_b])?.remove(0);

        Ok(ConfigStmtPath(stmt_p))
    }
    pub fn set_share(
        &self,
        act: &Act,
        share: Keyshare<E, G>,
        stmt: &SignedStatement,
    ) -> Result<KeysharePath> {
        assert!(matches!(act, Act::PostShare(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Keyshare));
        let share_b = share.ser();
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![share_b, stmt_b])?;
        let share_p = paths.remove(0);
        let stmt_p = paths.remove(0);

        Ok(KeysharePath(share_p, stmt_p))
    }
    pub fn set_pk(&self, act: &Act, pk: PublicKey<E, G>, stmt: &SignedStatement) -> Result<PkPath> {
        assert!(matches!(act, Act::CombineShares(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        let pk_b = pk.ser();
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![pk_b, stmt_b])?;
        let pk_p = paths.remove(0);
        let stmt_p = paths.remove(0);

        Ok(PkPath(pk_p, stmt_p))
    }
    pub fn set_pk_stmt(&self, act: &Act, stmt: &SignedStatement) -> Result<PkStmtPath> {
        assert!(matches!(act, Act::CheckPk(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![stmt_b])?;
        let stmt_p = paths.remove(0);

        Ok(PkStmtPath(stmt_p))
    }
    pub fn set_mix(&self, act: &Act, mix: Mix<E>, stmt: &SignedStatement) -> Result<MixPath> {
        assert!(matches!(act, Act::Mix(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Mix));
        let mix_b = mix.ser();
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![mix_b, stmt_b])?;
        let pk_p = paths.remove(0);
        let stmt_p = paths.remove(0);

        Ok(MixPath(pk_p, stmt_p))
    }
    pub fn set_mix_stmt(&self, act: &Act, stmt: &SignedStatement) -> Result<MixStmtPath> {
        assert!(matches!(act, Act::CheckMix(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Mix));
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![stmt_b])?;
        let stmt_p = paths.remove(0);

        Ok(MixStmtPath(stmt_p))
    }

    pub fn set_pdecryptions(
        &self,
        act: &Act,
        pdecryptions: PartialDecryption<E>,
        stmt: &SignedStatement,
    ) -> Result<PDecryptionsPath> {
        assert!(matches!(act, Act::PartialDecrypt(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PDecryption));
        let pdecryptions_b = pdecryptions.ser();
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![pdecryptions_b, stmt_b])?;
        let pdecryptions_p = paths.remove(0);
        let stmt_p = paths.remove(0);

        Ok(PDecryptionsPath(pdecryptions_p, stmt_p))
    }

    pub fn set_plaintexts(
        &self,
        act: &Act,
        plaintexts: Plaintexts<E>,
        stmt: &SignedStatement,
    ) -> Result<PlaintextsPath> {
        assert!(matches!(act, Act::CombineDecryptions(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Plaintexts));
        let plaintexts_b = plaintexts.ser();
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![plaintexts_b, stmt_b])?;
        let plaintexts_p = paths.remove(0);
        let stmt_p = paths.remove(0);

        Ok(PlaintextsPath(plaintexts_p, stmt_p))
    }
    pub fn set_plaintexts_stmt(
        &self,
        act: &Act,
        stmt: &SignedStatement,
    ) -> Result<PlaintextsStmtPath> {
        assert!(matches!(act, Act::CheckPlaintexts(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Plaintexts));
        let stmt_b = stmt.ser();
        let mut paths = self.set_work(act, vec![stmt_b])?;
        let stmt_p = paths.remove(0);

        Ok(PlaintextsStmtPath(stmt_p))
    }

    pub fn get_work(&self, action: &Act, _hash: hashing::Hash) -> Option<Vec<PathBuf>> {
        let target = self.path_for_action(action);
        let mut ret = Vec::new();
        for i in 0..10 {
            let with_ext = target.with_extension(i.to_string());
            if with_ext.exists() && with_ext.is_file() {
                ret.push(with_ext);
            } else {
                break;
            }
        }

        if !ret.is_empty() {
            Some(ret)
        } else {
            None
        }
    }

    fn set_work(&self, action: &Act, work: Vec<Vec<u8>>) -> Result<Vec<PathBuf>> {
        let target = self.path_for_action(action);
        let mut ret = Vec::new();

        for (i, item) in work.iter().enumerate() {
            let with_ext = target.with_extension(i.to_string());
            assert!(!with_ext.exists());
            util::write_file_bytes(&with_ext, item)?;
            ret.push(with_ext);
        }
        Ok(ret)
    }

    fn path_for_action(&self, action: &Act) -> PathBuf {
        let hash = hashing::hash(action);
        let encoded = hex::encode(&hash);
        let work_path = Path::new(&encoded);
        let ret = Path::new(&self.fs_path).join(work_path);

        ret
    }
}
