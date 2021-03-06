// cargo test demo --release -- --ignored

use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};

use curve25519_dalek::ristretto::RistrettoPoint;
use ed25519_dalek::{Keypair, PublicKey as SPublicKey};
use rand::rngs::OsRng;
use uuid::Uuid;

use braid::crypto::base::Element;
use braid::crypto::base::Group;
use braid::crypto::elgamal::PublicKey;
use braid::crypto::hashing;
use braid::data::artifact::*;
use braid::protocol::statement::SignedStatement;

use braid::bulletinboard::basic::*;
use braid::bulletinboard::generic::*;
use braid::bulletinboard::*;
use braid::crypto::backend::ristretto_b::*;
use braid::data::bytes::*;
use braid::protocol::facts::AllFacts;
use braid::protocol::logic::Driver;
use braid::protocol::trustee::Trustee;
use braid::protocol::trustee::TrusteeError;
use braid::util;

use cursive::align::HAlign;
use cursive::theme::BaseColor;
use cursive::theme::{Color, PaletteColor, Theme};
use cursive::traits::*;
use cursive::utils::markup::StyledString;
use cursive::view::ScrollStrategy;
use cursive::views::{LinearLayout, Panel, ScrollView, TextView};
use cursive::Cursive;

use log::info;
use regex::Regex;
use simplelog::*;

type DemoArc<E, G, B> = Arc<Mutex<Demo<E, G, B>>>;

struct Demo<E: Element, G, B> {
    pub cb_sink: cursive::CbSink,
    trustees: Vec<Driver<E, G, GenericBulletinBoard<E, G, B>>>,
    bb_keypair: Keypair,
    config: braid::data::artifact::Config<E, G>,
    all_plaintexts: Vec<Vec<E::Plaintext>>,
    ballots: u32,
    boards: Vec<GenericBulletinBoard<E, G, B>>,
}

impl<E: Element, G: Group<E>, B: BasicBoard> Demo<E, G, B>
where
    <E as Element>::Plaintext: std::hash::Hash,
{
    fn new(
        sink: cursive::CbSink,
        trustees: Vec<Driver<E, G, GenericBulletinBoard<E, G, B>>>,
        boards: Vec<GenericBulletinBoard<E, G, B>>,
        bb_keypair: Keypair,
        ballots: u32,
        cfg: braid::data::artifact::Config<E, G>,
    ) -> Demo<E, G, B> {
        Demo {
            cb_sink: sink,
            trustees,
            bb_keypair,
            config: cfg,
            boards,
            // board: bb,
            all_plaintexts: vec![],
            ballots,
        }
    }

    fn add_ballots(&mut self) {
        for i in 0..self.config.contests {
            let pk_b = self.boards[0]
                .get_unsafe(GenericBulletinBoard::<E, G, B>::public_key(i, 0))
                .unwrap();
            let ballots_b = self.boards[0]
                .get_unsafe(GenericBulletinBoard::<E, G, B>::ballots(i))
                .unwrap();
            if pk_b.is_some() && ballots_b.is_none() {
                info!(">> Adding {} ballots..", self.ballots);
                let pk = PublicKey::<E, G>::deser(&pk_b.unwrap()).unwrap();

                let (plaintexts, ciphertexts) =
                    util::random_encrypt_ballots(self.ballots as usize, &pk);
                self.all_plaintexts.push(plaintexts);

                let ballots = Ballots { ciphertexts };
                let ballots_b = ballots.ser();
                let ballots_h = hashing::hash(&ballots);
                let cfg_h = hashing::hash(&self.config);
                let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &self.bb_keypair);

                let ss_b = ss.ser();

                let f1 = util::write_tmp(ballots_b).unwrap();
                let f2 = util::write_tmp(ss_b).unwrap();

                self.boards[0]
                    .add_ballots(
                        &BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()),
                        i,
                    )
                    .unwrap();
                info!(">> OK");
            } else {
                info!(
                    "Cannot add ballots for contest=[{}] at this time (no pk yet?)",
                    i
                );
            }
        }
    }
    fn check_plaintexts(&self) {
        for i in 0..self.config.contests {
            if let Some(decrypted_b) = self.boards[0]
                .get_unsafe(GenericBulletinBoard::<E, G, B>::plaintexts(i, 0))
                .unwrap()
            {
                let decrypted = Plaintexts::<E>::deser(&decrypted_b).unwrap();
                let decoded: Vec<E::Plaintext> = decrypted
                    .plaintexts
                    .iter()
                    .map(|p| self.config.group.decode(&p))
                    .collect();
                let p1: HashSet<&E::Plaintext> =
                    HashSet::from_iter(self.all_plaintexts[i as usize].iter().clone());
                let p2: HashSet<&E::Plaintext> = HashSet::from_iter(decoded.iter().clone());

                info!(">> Checking plaintexts contest=[{}]...", i);
                assert!(p1 == p2);
                info!(">> OK");
            } else {
                info!(
                    "Cannot check plaintexts for contest=[{}], no decryptions yet",
                    i
                );
            }
        }
    }
    fn process_facts(&mut self, t: usize) -> AllFacts {
        let trustee = &self.trustees[t];
        if self.boards.len() > 1 {
            trustee.process_facts(&mut self.boards[t])
        } else {
            trustee.process_facts(&mut self.boards[0])
        }
    }
    fn run(&mut self, facts: AllFacts, t: usize) -> Result<u32, TrusteeError> {
        let trustee = &self.trustees[t];
        if self.boards.len() > 1 {
            trustee.run(facts, &mut self.boards[t])
        } else {
            trustee.run(facts, &mut self.boards[0])
        }
    }
    fn writer(&self) -> DemoLogSink {
        DemoLogSink {
            cb_sink: self.cb_sink.clone(),
            buffer: String::new(),
            target: String::from("0"),
        }
    }
    fn status(&self, status: String) {
        self.cb_sink
            .send(Box::new(move |s: &mut cursive::Cursive| {
                s.call_on_name("status", |view: &mut TextView| {
                    let styled = if status == *"Ready" {
                        StyledString::styled(status, Color::Light(BaseColor::Green))
                    } else {
                        StyledString::styled(status, Color::Light(BaseColor::Yellow))
                    };
                    view.set_content(styled);
                });
            }))
            .unwrap();
    }
    fn done(&self, trustee: u32) {
        self.cb_sink
            .send(Box::new(move |s: &mut cursive::Cursive| {
                s.call_on_name(&trustee.to_string(), |view: &mut ScrollView<TextView>| {
                    let current = view.get_inner_mut().get_content();
                    let t = String::from(current.source());
                    drop(current);
                    view.get_inner_mut()
                        .set_content(StyledString::styled(t, Color::Light(BaseColor::Green)));
                });
            }))
            .unwrap();
        self.status(String::from("Ready"));
    }
}

#[ignore]
#[test]
fn demo() {
    let mut n: u32 = 0;

    // let group = RugGroup::default();
    let group = RistrettoGroup;
    let trustees: u32 = 3;
    let contests = 3;
    let ballots = 2000;
    let mut bbs = Vec::new();
    let mut trustee_pks = Vec::new();
    let mut drivers = Vec::new();

    let basic = MBasic::default();
    let board = GenericBulletinBoard::<RistrettoPoint, RistrettoGroup, MBasic>::new(basic);
    bbs.push(board);

    for i in 0..trustees {
        /*
        GIT

        let basic = git_board(i);
        fs::remove_dir_all(&basic.fs_path).ok();
        if i == 0 {
            println!("Resetting remote repository..");
            basic.clone().unwrap();
            basic.__clear().unwrap();
        }

        let bb = GenericBulletinBoard::<RistrettoPoint, RistrettoGroup, GitBulletinBoard>::new(basic);
        bbs.push(bb);*/

        let local = format!("/tmp/local{}", i);
        let local_path = Path::new(&local);
        fs::remove_dir_all(local_path).ok();
        fs::create_dir(local_path).ok();

        let trustee: Trustee<RistrettoPoint, RistrettoGroup> = Trustee::new(local.to_string());
        trustee_pks.push(trustee.keypair.public);

        /*
        GIT

        let driver: Driver<RistrettoPoint, RistrettoGroup, GenericBulletinBoard<RistrettoPoint, RistrettoGroup, GitBulletinBoard>>
            = Driver::new(trustee);
        drivers.push(driver);*/

        let driver: Driver<
            RistrettoPoint,
            RistrettoGroup,
            GenericBulletinBoard<RistrettoPoint, RistrettoGroup, MBasic>,
        > = Driver::new(trustee);
        drivers.push(driver);
    }

    let mut csprng = OsRng;
    let bb_keypair = Keypair::generate(&mut csprng);

    let cfg = gen_config(&group, contests, trustee_pks, bb_keypair.public);
    let cfg_b = cfg.ser();
    let tmp_file = util::write_tmp(cfg_b).unwrap();
    println!("Adding config..");
    bbs[0]
        .add_config(&ConfigPath(tmp_file.path().to_path_buf()))
        .unwrap();

    let mut siv = cursive::default();
    let demo = Demo::new(
        siv.cb_sink().clone(),
        drivers,
        bbs,
        bb_keypair,
        ballots,
        cfg,
    );

    CombinedLogger::init(vec![
        // TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed),
        WriteLogger::new(
            LevelFilter::Warn,
            simplelog::Config::default(),
            File::create("/tmp/my.log").unwrap(),
        ),
        WriteLogger::new(
            LevelFilter::Info,
            simplelog::Config::default(),
            demo.writer(),
        ),
    ])
    .unwrap();

    let demo_arc_run = Arc::new(Mutex::new(demo));
    let demo_arc_ballots = Arc::clone(&demo_arc_run);
    let demo_arc_verify = Arc::clone(&demo_arc_run);
    let demo_arc_artifacts = Arc::clone(&demo_arc_run);

    let theme = custom_theme_from_cursive(&siv);
    siv.set_theme(theme);

    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let init_text = format!(
        "Build: {}\nGroup: {}\nTrustees: {}\nContests: {}\nBallots: {}",
        build,
        util::type_name_of(&group),
        trustees,
        contests,
        ballots
    );

    let mut h_layout = LinearLayout::horizontal();
    let mut layout = LinearLayout::vertical();

    for i in 0..trustees {
        let title = format!("Trustee {}", i);
        let text = "";
        layout = layout.child(
            Panel::new(
                TextView::new(text)
                    .scrollable()
                    .scroll_strategy(ScrollStrategy::StickToBottom)
                    .with_name(&i.to_string()),
            )
            .title(title)
            .title_position(HAlign::Left)
            .full_width()
            .full_height(),
        );
    }

    layout = layout.child(
        LinearLayout::horizontal()
            .child(
                Panel::new(TextView::new(
                    "[s Step] [b Add ballots] [c Check plaintexts] [i info] [q Quit]",
                ))
                .title("Commands")
                .title_position(HAlign::Left)
                .fixed_height(3)
                .full_width(),
            )
            .child(
                Panel::new(
                    TextView::new(StyledString::styled(
                        "Ready",
                        Color::Light(BaseColor::Green),
                    ))
                    .h_align(HAlign::Left)
                    .with_name("status"),
                )
                .fixed_width(12),
            ),
    );
    h_layout.add_child(layout);
    h_layout.add_child(
        Panel::new(
            TextView::new(init_text.clone())
                .scrollable()
                .scroll_strategy(ScrollStrategy::StickToBottom)
                .with_name("facts"),
        )
        .title("Facts")
        .title_position(HAlign::Left)
        .fixed_width(95)
        .full_height(),
    );
    // siv.add_fullscreen_layer(h_layout);
    siv.add_layer(h_layout);
    siv.add_global_callback('q', |s| s.quit());
    siv.add_global_callback('s', move |s| {
        let guard = Arc::clone(&demo_arc_run);
        if guard.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            s.call_on_name(&"facts".to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            step_t(Arc::clone(&demo_arc_run), n);
            n = (n + 1) % trustees;
        }
    });
    siv.add_global_callback('b', move |s| {
        let guard = Arc::clone(&demo_arc_ballots);
        if guard.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            ballots_t(Arc::clone(&demo_arc_ballots), 0);
        }
    });
    siv.add_global_callback('c', move |s| {
        let guard = Arc::clone(&demo_arc_verify);
        if guard.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            check_t(Arc::clone(&demo_arc_verify), 0);
        }
    });
    siv.add_global_callback('i', move |s| {
        let text = init_text.clone();
        let guard = Arc::clone(&demo_arc_artifacts);
        let demo = guard.lock().unwrap();
        let mut artifacts = demo.boards[0].list().unwrap();
        artifacts.sort();
        let artifacts = artifacts.join("\n");

        s.call_on_name("facts", |view: &mut ScrollView<TextView>| {
            view.get_inner_mut().set_content(text);
            view.get_inner_mut().append("\n\nArtifacts:\n");
            view.get_inner_mut().append(artifacts);
        });
    });

    siv.run();
}

fn step_t<
    E: 'static + Element + std::cmp::PartialEq,
    G: 'static + Group<E>,
    B: 'static + BasicBoard + Send + Sync,
>(
    demo_arc: DemoArc<E, G, B>,
    t: u32,
) where
    <E as Element>::Plaintext: std::hash::Hash,
{
    std::thread::spawn(move || step(Arc::clone(&demo_arc), t));
}

fn ballots_t<
    E: 'static + Element + std::cmp::PartialEq,
    G: 'static + Group<E>,
    B: 'static + BasicBoard + Send + Sync,
>(
    demo_arc: DemoArc<E, G, B>,
    t: u32,
) where
    <E as Element>::Plaintext: std::hash::Hash,
{
    std::thread::spawn(move || ballots(Arc::clone(&demo_arc), t));
}

fn check_t<
    E: 'static + Element + std::cmp::PartialEq,
    G: 'static + Group<E>,
    B: 'static + BasicBoard + Send + Sync,
>(
    demo_arc: DemoArc<E, G, B>,
    t: u32,
) where
    <E as Element>::Plaintext: std::hash::Hash,
{
    std::thread::spawn(move || check(Arc::clone(&demo_arc), t));
}

fn step<E: Element + std::cmp::PartialEq, G: Group<E>, B: BasicBoard + Send + Sync>(
    demo_arc: DemoArc<E, G, B>,
    t: u32,
) where
    <E as Element>::Plaintext: std::hash::Hash,
{
    let mut demo = demo_arc.lock().unwrap();
    demo.status(String::from("Working..."));
    info!("set_panel=[facts]");
    info!("Trustee [{}] process_facts..", t);
    let facts = demo.process_facts(t as usize);
    info!("set_panel=[{}]", t);
    demo.run(facts, t as usize).unwrap();
    demo.done(t);
}

fn ballots<E: Element + std::cmp::PartialEq, G: Group<E>, B: BasicBoard + Send + Sync>(
    demo_arc: DemoArc<E, G, B>,
    t: u32,
) where
    <E as Element>::Plaintext: std::hash::Hash,
{
    let mut demo = demo_arc.lock().unwrap();
    demo.status(String::from("Working..."));
    info!("set_panel=[{}]", t);
    demo.add_ballots();
    demo.done(t);
}

fn check<
    E: 'static + Element + std::cmp::PartialEq,
    G: 'static + Group<E>,
    B: BasicBoard + Send + Sync,
>(
    demo_arc: DemoArc<E, G, B>,
    t: u32,
) where
    <E as Element>::Plaintext: std::hash::Hash,
{
    let demo = demo_arc.lock().unwrap();
    demo.status(String::from("Working..."));
    info!("set_panel=[{}]", t);
    demo.check_plaintexts();
    demo.done(t);
}

fn custom_theme_from_cursive(siv: &Cursive) -> Theme {
    let mut theme = siv.current_theme().clone();

    theme.palette[PaletteColor::Background] = Color::TerminalDefault;
    theme.palette[PaletteColor::Primary] = Color::Rgb(170, 170, 170);
    theme.palette[PaletteColor::View] = Color::TerminalDefault;

    theme
}

struct DemoLogSink {
    pub cb_sink: cursive::CbSink,
    pub buffer: String,
    target: String,
}
impl std::io::Write for DemoLogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let re = Regex::new("set_panel=\\[([a-z0-9]+)\\]").unwrap();

        let string = String::from(std::str::from_utf8(&buf).unwrap());
        self.buffer.push_str(&string);
        if self.buffer.contains('\n') {
            let split: Vec<&str> = self.buffer.split('\n').collect();
            let items = split.len();
            let head = &split[0..items - 1];

            for next in head {
                if let Some(captures) = re.captures(next) {
                    let capture = captures.get(1).unwrap().as_str();
                    let target = self.target.clone();
                    self.cb_sink
                        .send(Box::new(move |s: &mut cursive::Cursive| {
                            s.call_on_name(&target, |view: &mut ScrollView<TextView>| {
                                let current = view.get_inner_mut().get_content();
                                let t = String::from(current.source());
                                drop(current);
                                view.get_inner_mut().set_content(t);
                            });
                        }))
                        .unwrap();
                    self.target = capture.to_string();
                } else {
                    self.send_line(next.to_string());
                }
            }
            self.buffer = split[items - 1].to_string();
        }

        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DemoLogSink {
    fn send_line(&self, line: String) {
        let line = format!("{}\n", line);
        let target = self.target.clone();
        self.cb_sink
            .send(Box::new(move |s: &mut cursive::Cursive| {
                s.call_on_name(&target, |view: &mut ScrollView<TextView>| {
                    let styled = StyledString::styled(line, Color::Light(BaseColor::Yellow));
                    view.get_inner_mut().append(styled);
                    view.scroll_to_bottom();
                });
            }))
            .unwrap();
    }
}

fn gen_config<E: Element, G: Group<E>>(
    group: &G,
    contests: u32,
    trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey,
) -> braid::data::artifact::Config<E, G> {
    let id = Uuid::new_v4();

    let cfg = braid::data::artifact::Config {
        id: *id.as_bytes(),
        group: group.clone(),
        contests,
        ballotbox: ballotbox_pk,
        trustees: trustee_pks,
        phantom_e: PhantomData,
    };

    cfg
}

use braid::bulletinboard::git;
use braid::bulletinboard::git::GitBulletinBoard;

fn git_board(i: u32) -> GitBulletinBoard {
    let mut board = git::test_config();
    board.fs_path = std::format!("/tmp/repo{}", i);

    board
}
