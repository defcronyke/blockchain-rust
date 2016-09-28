extern crate crypto;
extern crate time;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

#[derive(Debug, Clone)]
pub enum NodeE {
	Parent(Box<Node>),
	Start,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub hash: String,
    pub value: String,
    pub parent: NodeE,
}

impl Node {
	
	pub fn new(val: &str) -> Box<Node> {
		
		let mut hasher = Sha256::new();
		
		// TODO: Add some random bytes to the hasher input.
		hasher.input_str(&((time::get_time().nsec as i64).to_string() + val));
		
		Box::new(Node{
			hash: hasher.result_str(),
			value: val.to_owned(),
			parent: NodeE::Start,
		})
	}
	
	pub fn commit(self, val: &str) -> Box<Node> {
		let mut n = Node::new(val);
		n.parent = NodeE::Parent(Box::new(self.clone()));
		
		let mut hasher = Sha256::new();
		hasher.input_str(&format!("{}{}", self.hash, self.value));
		n.hash = hasher.result_str();
		
		n
	}
	
	pub fn height(self) -> u64 {
		let mut c = 1u64;
		let mut n = self;
		loop {
			match n.parent {
				NodeE::Start => break,
				NodeE::Parent(p) => {
					c = c + 1;
					n = *p;
				} 
			}
		}
		c
	}
	
	pub fn verify(self) -> bool {
		let mut res = true;
		let mut n = self.clone();
		
		loop {
			let mut hasher = Sha256::new();
			
			match n.parent.clone() {
				NodeE::Parent(p) => {
					hasher.input_str(&format!("{}{}", p.clone().hash, p.clone().value));
					if hasher.result_str() != n.hash {
						println!("Error: Blockchain failed verification at block {}: {:?}", p.clone().height(), p.clone());
						res = false;
						break;
					}
					n = *p
				},
				NodeE::Start => {
					break;
				}
			}
		}
		
		res
	}
}

#[cfg(test)]
mod tests {
    use super::*;
    use NodeE::*;
    
    #[test]
    fn valid_blockchain_is_valid() {
	    let b = Node::new("hello").commit("1").commit("2");
	    assert!(b.verify());
    }
    
    #[test]
    fn value_tampered_blockchain_is_invalid() {
	    let mut b = Node::new("hello").commit("1").commit("2");
	    
		match b.parent {
        	Parent(ref mut b) => {
        		b.value = "pies".to_owned();
        	},
        	_ => {}
        }
	    
	    assert!(!b.verify());
    }
    
    #[test]
    fn hash_tampered_blockchain_is_invalid() {
	    let mut b = Node::new("hello").commit("1").commit("2");
	    
		match b.parent {
        	Parent(ref mut b) => {
        		b.hash = "hash pies".to_owned();
        	},
        	_ => {}
        }
	    
	    assert!(!b.verify());
    }
    
    #[test]
    fn parent_tampered_blockchain_is_invalid() {
	    let mut b = Node::new("hello").commit("1").commit("2");
	    
		match b.parent {
        	Parent(ref mut b) => {
        		
        		match b.clone().parent {
        			Parent(ref mut b2) => {
        				let n = Node{
							hash: b2.clone().hash,
							value: "bad parent".to_owned(),
							parent: b2.clone().parent,
						};
        				
        				b.parent = Parent(Box::new(n));
        			},
        		    _ => {
        		    	
        		    }
        		}
        	},
        	_ => {}
        }
	    
	    assert!(!b.verify());
    }
}
