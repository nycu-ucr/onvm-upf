#include "TupleSpaceSearch.h"
#include "hash.h"

// Values for Bernstein Hash
#define HashBasis 5381
#define HashMult 33


#ifndef tss_hash_add
static inline uint32_t tss_hash_add(uint32_t h, uint32_t v)
{  /* tiny Bernstein mix, identical to OVS helpers */
    h += v;  h += (h << 10);  h ^= (h >> 6);
    return h;
}
static inline uint32_t hash_finish(uint32_t h, int bits)
{
    h += (h << 3);  h ^= (h >> 11);  h += (h << 15);
    if (bits < 32) h &= (1u << bits) - 1;
    return h;
}
#endif

// cmap_node* Tuple::InsertionReturnNode(const Rule& r) {
//     cmap_node* n = new cmap_node;
//     n->priority  = r.priority;       // stored priority
//     n->desc      = r.descriptor;     // opaque handle
//     n->rule_ptr  = new Rule(r);      // own a copy of the Rule
//     n->next      = nullptr;

//     uint32_t hv = HashRule(r);
//     cmap_insert(&map_in_tuple, n, hv);
//     return n;
// }


// void Tuple::Insertion(const Rule& r) {
//     auto *node     = new cmap_node;
//     node->priority = r.priority;
//     node->desc     = r.descriptor;
//     node->rule_ptr = &r;
//     cmap_insert(&map_in_tuple, node, HashRule(r));
// }


// void Tuple::Insertion(const Rule& r) {

// 	cmap_node * new_node = new cmap_node(r); /*key & rule*/
// 	cmap_insert(&map_in_tuple, new_node, HashRule(r));

// 	/*uint32_t key = HashRule(r);
// 	std::vector<Rule>& rl = table[key];
// 	rl.push_back(r);
// 	sort(rl.begin(), rl.end(), [](const Rule& rx, const Rule& ry) { return rx.priority >= ry.priority; });*/
// }

/*
Modification: write the bucket key into the node before calling cmap_insert(). 
Without that, cmap_remove() silently refuses to unlink it
*/

void Tuple::Insertion(const Rule& r) {
    uint32_t h       = HashRule(r);        // compute the bucket hash
    cmap_node *node  = new cmap_node(r);   // ctor copies priority/desc/rule
    node->key        = h;                  // <-- store it for later removal
    cmap_insert(&map_in_tuple, node, h);
}


// void Tuple::Deletion(const Rule& r) {
// 	//find node containing the rule
//     unsigned int hash_r = HashRule(r);
//     cmap_node *found = cmap_find(&map_in_tuple, hash_r);
//     while (found) {
//         if (found->priority == r.priority) {
//             cmap_remove(&map_in_tuple, found, hash_r);
// 			delete found->rule_ptr;
//     		delete found;
//             break;
//         }
//         found = found->next;
//     }
// }

void Tuple::Deletion(const Rule& r) {
	//find node containing the rule
	unsigned int hash_r = HashRule(r);
	cmap_node * found_node = cmap_find(&map_in_tuple, hash_r);
	while (found_node != nullptr) {
		if (found_node->priority == r.priority) {
			cmap_remove(&map_in_tuple, found_node, hash_r);
			delete found_node;
			break;
		}
		found_node = found_node->next;
	}

	/*uint32_t key = HashRule(r);
	std::vector<Rule>& rl = table[key];
	rl.erase(std::remove_if(rl.begin(), rl.end(), [=](const Rule& ri) { return ri.priority == r.priority; }), rl.end());*/
}



int Tuple::WorstAccesses() const {
	// TODO
	return 1;//cmap_largest_chain(&map_in_tuple);
}

int Tuple::FindMatchPacket(const Packet& p)  {
	
	cmap_node * found_node = cmap_find(&map_in_tuple, HashPacket(p));
	int priority = -1;
	while (found_node != nullptr) {
		if (found_node->rule_ptr->MatchesPacket(p)) {
			priority = std::max(priority, found_node->priority);
		}
		found_node = found_node->next;
	}
	return priority;

/*	auto ptr = table.find(HashPacket(p));
	if (ptr != table.end()) {
		for (const Rule& r : ptr->second) {
			if (r.MatchesPacket(p)) {
				return r.priority;
			}
		}
	}
	return -1;*/
}

MatchResult Tuple::FindMatchPacketMod(const Packet& p) const {
    MatchResult best{-1, 0};
    cmap_node *n = cmap_find(&map_in_tuple, HashPacket(p));
    while (n) {
        if (n->rule_ptr->MatchesPacket(p) && n->priority > best.priority)
            best = { n->priority, n->desc };
        n = n->next;
    }
    return best;
}


bool inline Tuple::IsPacketMatchToRule(const Packet& p, const Rule& r) {
    for (int i = 0; i < r.dim; ++i) {
        if (p[i] < r.range[i][LowDim] || p[i] > r.range[i][HighDim])
            return false;
    }
    return true;
}


uint32_t inline Tuple::HashRule(const Rule& r) const {
	uint32_t hash = 0;
	for (size_t i = 0; i < dims.size(); i++) {
		hash = tss_hash_add(hash, r.range[dims[i]][LowDim]);
	}
	return hash_finish(hash, 16);

/*	uint32_t hash = HashBasis;
	for (size_t d = 0; d < tuple.size(); d++) {
		hash *= HashMult;
		hash += r.range[d][LowDim] & ForgeUtils::Mask(tuple[d]);
	}
	return hash;*/

}


uint32_t inline Tuple::HashPacket(const Packet& p) const {
	uint32_t hash = 0;
	uint32_t max_uint = 0xFFFFFFFF;

	for (size_t i = 0; i < dims.size(); i++) {
		uint32_t mask = lengths[i] != 32 ? ~(max_uint >> lengths[i]) : max_uint;
		hash = tss_hash_add(hash, p[dims[i]] & mask);
	}
	return hash_finish(hash, 16);

	/*uint32_t hash = HashBasis;
	for (size_t d = 0; d < tuple.size(); d++) {
		hash *= HashMult;
		hash += p[d] & ForgeUtils::Mask(tuple[d]);
	}
	return hash;*/
}


void TupleSpaceSearch::ConstructClassifier(const std::vector<Rule>& r){
	/*int multiples = 5;
	for (int i = 0; i < r[0].dim / multiples; i++) {
		dims.push_back(i * multiples);
		dims.push_back(i * multiples + 1);
	}*/
	dims.push_back(FieldSA);
	dims.push_back(FieldDA);

	for (const auto& Rule : r) {
		InsertRule(Rule);
	}

	rules = r;
	rules.reserve(100000);
}


int TupleSpaceSearch::ClassifyAPacket(const Packet& packet) {
	int priority = -1;
	int query = 0;
	for (auto& tuple : all_tuples) {
		auto result = tuple.second.FindMatchPacket(packet);
		priority = std::max(priority, result);
		query++;
	}
	// QueryUpdate(query);
	return priority;
}

MatchResult TupleSpaceSearch::ClassifyAPacketMod(const Packet& pkt) const {
    MatchResult best{-1, 0};
    for (const auto& kv : all_tuples) {
        auto m = kv.second.FindMatchPacketMod(pkt);
        if (m.priority > best.priority)
            best = m;
    }
    return best;
}


// void TupleSpaceSearch::DeleteRule(size_t i) {

// 	if (i < 0 || i >= rules.size()) {
// 		printf("Warning index delete rule out of bound: do nothing here\n");
// 		printf("%lu vs. size: %lu", i, rules.size());
// 		return;
// 	}

// 	auto hit = all_tuples.find(KeyRulePrefix(rules[i]));
// 	if (hit != end(all_tuples)) {
// 		desc_map.erase(rules[i].descriptor);
// 		//there is a tuple
// 		hit->second.Deletion(rules[i]);
// 		if (hit->second.IsEmpty()) {
// 			//destroy tuple and erase from the map
// 			hit->second.Destroy();
// 			all_tuples.erase(hit);
// 		}
// 	} else {
// 		//nothing to do?
// 		printf("Warning DeleteRule: no matching tuple in the rule; it should be here when inserted\n");
// 		exit(0);
// 	}
// 	if (i != rules.size() - 1)
// 		rules[i] = std::move(rules[rules.size() - 1]);
// 	rules.pop_back();
// }


void TupleSpaceSearch::DeleteRule(size_t i) {
    if (i >= rules.size()) return;
    auto const& r = rules[i];
    // remove from desc_map and cmap
    DeleteRuleByDescriptor(r.descriptor);
    // remove from rules vector
    if (i + 1 < rules.size())
        rules[i] = rules.back();
    rules.pop_back();
}



bool TupleSpaceSearch::DeleteRuleByDescriptor(uintptr_t desc) {
    auto it = desc_map.find(desc);
    if (it == desc_map.end()) return false;           // not found

    Tuple      *tuple = it->second.first;
    cmap_node  *node  = it->second.second;

    /* unlink from cmap chain */
    cmap_remove(
		&tuple->map_in_tuple,
		node,
		tuple->HashRule(*node->rule_ptr)
	);

    /* cleanup */
    delete node;
    desc_map.erase(it);

    /* if tuple became empty, kill it */
    if (tuple->IsEmpty()) {
        for (auto ti = all_tuples.begin(); ti != all_tuples.end(); ++ti) {
			if (&ti->second == tuple) {
				all_tuples.erase(ti); 
				break;
			}
		} 
            
    }

	for (size_t i = 0; i < rules.size(); ++i) {
		if (rules[i].descriptor == desc) {
			// Move the last element into slot i, then pop the back
			rules[i] = std::move(rules.back());
			rules.pop_back();
			break;
		}
	}


    return true;
}



// void TupleSpaceSearch::InsertRule(const Rule& rule) {
// 	auto hit = all_tuples.find(KeyRulePrefix(rule));
// 	if (hit != end(all_tuples)) {
// 		//there is a tuple
// 		hit->second.Insertion(rule);
// 	} else {
// 		//create_tuple
// 		std::vector<unsigned int> lengths;
// 		for (int d : dims) {
// 			lengths.push_back(rule.prefix_length[d]);
// 		}
// 		all_tuples.insert(std::make_pair(KeyRulePrefix(rule), Tuple(dims, lengths, rule)));
// 	}
// 	desc_map[rule.descriptor] = { 
// 		&all_tuples[key], 
// 		cmap_find(&all_tuples[key].map_in_tuple,
// 		all_tuples[key].HashRule(rule)) 
// 	};

// 	rules.push_back(rule);
// }



void TupleSpaceSearch::InsertRule(const Rule& rule) {
    // Compute the tuple-space key from the rule’s prefix lengths
    uint64_t key = KeyRulePrefix(rule);

    // Find—or create—the Tuple bucket for this key
    Tuple* t;
    auto it = all_tuples.find(key);
    if (it != all_tuples.end()) {
        
        t = &it->second;
        auto *n = new cmap_node(rule);  // uses ctor cmap_node(const Rule&)
		n->key    = t->HashRule(rule); 	// store key before insert
        cmap_insert(&t->map_in_tuple, n, n->key);
        desc_map[rule.descriptor] = { t, n };

    } else {
        // no tuple yet: build the lengths vector and construct one
        std::vector<unsigned int> lengths;
        for (int d : dims) {
            lengths.push_back(rule.prefix_length[d]);
        }
        auto inserted = all_tuples.emplace(
            key,
            Tuple(dims, lengths, rule)
        );
        t = &inserted.first->second;
		/* the Tuple ctor already inserted one node for us             */
        cmap_node *n = cmap_find(&t->map_in_tuple, t->HashRule(rule));
        desc_map[rule.descriptor] = { t, n };
    }

    rules.push_back(rule);
}


// void TupleSpaceSearch::InsertRule(const Rule& r) {
//     uint64_t key = KeyRulePrefix(r);

//     // 1) locate or create the Tuple bucket
//     Tuple* t;
//     auto it = all_tuples.find(key);
//     if (it == all_tuples.end()) {
//         // construct empty Tuple (no rule inserted yet)
//         std::vector<unsigned> lens;
//         for (int d : dims) lens.push_back(r.prefix_length[d]);
//         auto ins = all_tuples.emplace(key, Tuple(dims, lens));
//         t = &ins.first->second;
//     } else {
//         t = &it->second;
//     }

//     // 2) do the single insert & get back the node
//     cmap_node* node = t->InsertionReturnNode(r);

//     // 3) register for delete‐by‐descriptor
//     desc_map[r.descriptor] = { t, node };

//     // 4) track rule ordering
//     rules.push_back(r);
// }





int TupleSpaceSearch::WorstAccesses() const {
	int cost = 0;
	for (auto pair : all_tuples) {
		cost += pair.second.WorstAccesses() + 1;
	}
	return cost;
}

void PriorityTuple::Insertion(const Rule& r, bool& priority_change) {

	if (r.priority > maxPriority) {
		maxPriority = r.priority;
		priority_change = true;
	}
	priority_container.insert(r.priority);
	Tuple::Insertion(r);
}

void  PriorityTuple::Deletion(const Rule& r, bool& priority_change) {

	auto pit = priority_container.equal_range(r.priority);
	priority_container.erase(pit.first);
	if (priority_container.size() == 0)  {
		maxPriority = -1;
		priority_change = true;
	} else if (r.priority == maxPriority) {
		maxPriority = *priority_container.rbegin();
		priority_change = true;
	} else priority_change = false;
	Tuple::Deletion(r);
}


int PriorityTupleSpaceSearch::ClassifyAPacket(const Packet& packet) {
	int priority = -1;
	int q = 0;
	for (auto& tuple : priority_tuples_vector) {
		//if (tuple->maxPriority < 0) printf("priority %d\n", tuple->maxPriority);
		if (priority > tuple->maxPriority) break;
		auto result = tuple->FindMatchPacket(packet);
		q++;
		priority = priority > result ? priority : result;
	}
	// QueryUpdate(q);
	return priority;
}

MatchResult PriorityTupleSpaceSearch::ClassifyAPacketMod(const Packet& pkt) const {
    MatchResult best{-1, 0};
    for (auto* t : priority_tuples_vector) {
        if (best.priority > t->maxPriority) 
		break;
        auto m = t->FindMatchPacketMod(pkt);
        if (m.priority > best.priority)
            best = m;
    }
    return best;
}

// void PriorityTupleSpaceSearch::DeleteRule(size_t i) {
// 	if (i < 0 || i >= rules.size()) {
// 		printf("Warning index delete rule out of bound: do nothing here\n");
// 		printf("%lu vs. size: %lu", i, rules.size());
// 		return;
// 	}
// 	bool priority_change = false;

// 	auto hit = all_priority_tuples.find(KeyRulePrefix(rules[i]));

// 	if (hit != end(all_priority_tuples)) {
// 		//there is a tuple
// 		hit->second->Deletion(rules[i], priority_change);
// 		if (hit->second->IsEmpty()) {
// 			//destroy tuple and erase from the map
			
// 			all_priority_tuples.erase(hit);
// 			hit->second->Destroy();
// 			RetainInvaraintOfPriorityVector();
// 			priority_tuples_vector.pop_back();

// 		} else if (priority_change) {
// 			//sort tuple again
// 			RetainInvaraintOfPriorityVector();
// 		}

// 	} else {
// 		//nothing to do?
// 		printf("Warning DeleteRule: no matching tuple in the rule; it should be here when inserted\n");
// 		exit(0);
// 	}
// 	if (i != rules.size() - 1)
// 		rules[i] = std::move(rules[rules.size() - 1]);
// 	rules.pop_back();

// }


void PriorityTupleSpaceSearch::DeleteRule(size_t i) {
    if (i >= rules.size()) return;
    auto const& r = rules[i];
    DeleteRuleByDescriptor(r.descriptor);

    if (i + 1 < rules.size())
        rules[i] = rules.back();
    rules.pop_back();
}




bool PriorityTupleSpaceSearch::DeleteRuleByDescriptor(uintptr_t d) {
    auto it = desc_map.find(d);
    if (it == desc_map.end()) return false;

    // 1) pull out everything we’ll need, before deleting the node
    auto *pt   = static_cast<PriorityTuple*>(it->second.first);
    auto *node = it->second.second;

    // copy key & priority from the node safely
    Rule   rule_copy = *node->rule_ptr;       // grab a copy of the Rule
    uint64_t key     = KeyRulePrefix(rule_copy);
    int      pr      = node->priority;

    // 2) unlink & delete the node
    cmap_remove(&pt->map_in_tuple,
                node,
                pt->HashRule(rule_copy));
    delete node;      // now it’s safe

    // 3) remove descriptor from our map
    desc_map.erase(it);

    // 4) remove exactly that priority from the multiset
    auto pit = pt->priority_container.find(pr);
    if (pit != pt->priority_container.end())
        pt->priority_container.erase(pit);

    // update maxPriority
    if (pt->priority_container.empty())
        pt->maxPriority = -1;
    else
        pt->maxPriority = *pt->priority_container.rbegin();

    // 5) if that bucket emptied out, tear down the tuple entirely
    if (pt->IsEmpty()) {
        all_priority_tuples.erase(key);

        // remove from the sorted vector
        priority_tuples_vector.erase(
          std::remove(begin(priority_tuples_vector),
                      end(priority_tuples_vector),
                      pt),
          end(priority_tuples_vector)
        );
        delete pt;
    }

	for (size_t i = 0; i < rules.size(); ++i) {
		if (rules[i].descriptor == d) {
			// Move the last element into slot i, then pop the back
			rules[i] = std::move(rules.back());
			rules.pop_back();
			break;
		}
	}


    return true;
}






// void PriorityTupleSpaceSearch::InsertRule(const Rule& rule) {
// 	bool priority_change = false;
// 	auto hit = all_priority_tuples.find(KeyRulePrefix(rule));
// 	if (hit != end(all_priority_tuples)) {
// 		//there is a tuple
// 		hit->second->Insertion(rule, priority_change);
// 		if (priority_change) {
// 			RetainInvaraintOfPriorityVector();
// 		}
// 	} else {
// 		//create_tuple
// 		std::vector<unsigned int> lengths;
// 		for (int d : dims) {
// 			lengths.push_back(rule.prefix_length[d]);
// 		}
// 		auto ptuple = new PriorityTuple(dims, lengths, rule);
// 		all_priority_tuples.insert(std::make_pair(KeyRulePrefix(rule), ptuple));
// 		// add to priority vector
// 		priority_tuples_vector.push_back(ptuple);
// 		RetainInvaraintOfPriorityVector();
// 	}
// 	rules.push_back(rule);
// }


// void PriorityTupleSpaceSearch::InsertRule(const Rule& rule) {
//     bool priority_change = false;

//     /* --- locate or create the tuple -------------------------------- */
//     uint64_t key = KeyRulePrefix(rule);
//     PriorityTuple *pt;
//     auto hit = all_priority_tuples.find(key);

//     if (hit != all_priority_tuples.end()) {
//         pt = hit->second;
//         pt->Insertion(rule, priority_change);
//         if (priority_change) {
// 			RetainInvaraintOfPriorityVector();
// 		}
//     } else {
//         std::vector<unsigned> lens;
//         for (int d : dims) {
// 			lens.push_back(rule.prefix_length[d]);
// 		}

//         pt = new PriorityTuple(dims, lens, rule);
//         all_priority_tuples.emplace(key, pt);
//         priority_tuples_vector.push_back(pt);
//         RetainInvaraintOfPriorityVector();
//     }

//     /* --- register (descriptor → Tuple*, node) for O(1) delete ------- */
//     uint32_t hv  = pt->HashRule(rule);
//     cmap_node *n = cmap_find(&pt->map_in_tuple, hv);
//     while (n && n->desc != rule.descriptor) {	    // walk if bucket collides
//         n = n->next;
// 	}

//     desc_map[rule.descriptor] = { pt, n };

//     /* --- book-keeping ---------------------------------------------- */
//     rules.push_back(rule);
// }


void PriorityTupleSpaceSearch::InsertRule(const Rule& r)
{
    bool pri_change = false;
    uint64_t key    = KeyRulePrefix(r);
    PriorityTuple *pt;

    /* ------------------------------------------------------------ */
    /* 1) locate or create the PriorityTuple bucket                 */
    /* ------------------------------------------------------------ */
    auto hit = all_priority_tuples.find(key);
    if (hit != all_priority_tuples.end()) {
        pt = hit->second;

        /* allocate a *safe* cmap_node that owns its Rule copy      */
        auto *n = new cmap_node(r);
		n->key    = pt->HashRule(r);
        cmap_insert(&pt->map_in_tuple, n, n->key);
        desc_map[r.descriptor] = { pt, n };

        /* keep max-priority bookkeeping                           */
        pt->priority_container.insert(r.priority);
        if (r.priority > pt->maxPriority) {
            pt->maxPriority = r.priority;
            pri_change = true;
        }
    } else {
        /* first rule for this tuple → build the tuple             */
        std::vector<unsigned> lens;
        for (int d : dims) lens.push_back(r.prefix_length[d]);

        pt = new PriorityTuple(dims, lens, r);           // ctor inserts 1 node
        all_priority_tuples.emplace(key, pt);
        priority_tuples_vector.push_back(pt);

        /* grab that first node for desc-map                       */
        cmap_node *n = cmap_find(&pt->map_in_tuple, pt->HashRule(r));
        desc_map[r.descriptor] = { pt, n };

        pri_change = true;                               // new tuple ⇒ resort
    }

    /* resort vector only if the tuple’s max-priority changed      */
    if (pri_change) RetainInvaraintOfPriorityVector();

    rules.push_back(r);
}


int PriorityTupleSpaceSearch::WorstAccesses() const {
	int cost = 0;
	for (const PriorityTuple* t : priority_tuples_vector) {
		cost += t->WorstAccesses() + 1;
	}
	return cost;
}
