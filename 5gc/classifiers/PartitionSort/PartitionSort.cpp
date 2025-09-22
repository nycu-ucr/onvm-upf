#include <inttypes.h>
#include <cstdio>
#include "Common.h"
#include "PartitionSort.h"

//thread_local uintptr_t CURRENT_DESCRIPTOR = 0;

void PartitionSort::InsertRule(const Rule& one_rule) {

	//CURRENT_DESCRIPTOR = one_rule.descriptor;

	for (auto mitree : mitrees)
	{
		bool prioritychange = false;
		
		bool success = mitree->TryInsertion(one_rule, prioritychange);
		if (success) {
			
			if (prioritychange) {
				InsertionSortMITrees();
			}
			mitree->ReconstructIfNumRulesLessThanOrEqualTo(10);
			rules.push_back(std::make_pair(one_rule, mitree));
			return;
		}
	}
	bool priority_change = false;
	 
	auto tree_ptr = new OptimizedMITree(one_rule);
	tree_ptr->TryInsertion(one_rule, priority_change);
	rules.push_back(std::make_pair(one_rule, tree_ptr));
	mitrees.push_back(tree_ptr);  
	InsertionSortMITrees();

	size_t idx = rules.size() - 1;
    descriptorIndexMap[one_rule.descriptor] = idx;
    //return idx;

}

uintptr_t PartitionSort::InsertRuleReturnDescriptor(const Rule& one_rule) {
    try {
        for (auto* mitree : mitrees) {
            bool pri_change = false;
            if (mitree->TryInsertion(one_rule, pri_change)) {
                if (pri_change) InsertionSortMITrees();
                // mitree->ReconstructIfNumRulesLessThanOrEqualTo(10);
                rules.emplace_back(one_rule, mitree);
                descriptorIndexMap[one_rule.descriptor] = rules.size() - 1;
                return one_rule.descriptor;
            }
        }
        auto* tree_ptr = new OptimizedMITree(one_rule);
        bool dummy = false;
        tree_ptr->TryInsertion(one_rule, dummy);
        mitrees.push_back(tree_ptr);
        InsertionSortMITrees();
        rules.emplace_back(one_rule, tree_ptr);

		// Populating descriptorIndexMap, so that I can delete by descriptor in O(1)

        descriptorIndexMap[one_rule.descriptor] = rules.size() - 1;
        return one_rule.descriptor;

    } catch (const std::bad_alloc&) {
        return 0;
    }
}




void PartitionSort::DeleteRule(size_t i){
	
	if (i >= rules.size()) {
        printf("Warning: delete index %zu out of bounds (size=%zu), no-op\n",
               i, rules.size());
        return;
    }
	
	// remove the map entry for the rule we're deleting

	uintptr_t desc = rules[i].first.descriptor;
  	descriptorIndexMap.erase(desc);

	//CURRENT_DESCRIPTOR = rules[i].first.descriptor;

	bool prioritychange = false;

	OptimizedMITree * mitree = rules[i].second; 
	mitree->Deletion(rules[i].first, prioritychange); 
 
	if (prioritychange) {
		InsertionSortMITrees();
	}


	if (mitree->Empty()) {
		mitrees.pop_back();
		delete mitree;
	}

	if (i != rules.size() - 1) {
		rules[i] = std::move(rules[rules.size() - 1]);
	}
	rules.pop_back();

	// if we didn’t just remove the very last element, 
	// Update the map for the rule that got moved into slot i
   
	if (i < rules.size()) {
        uintptr_t movedDesc = rules[i].first.descriptor;
        descriptorIndexMap[movedDesc] = i;
    }

}

bool PartitionSort::DeleteRuleByDescriptor(uintptr_t descriptor) {
  auto it = descriptorIndexMap.find(descriptor);
  if (it == descriptorIndexMap.end())
    return false;
  size_t idx = it->second;
  DeleteRule(idx);
  return true;
}


void PartitionSort::PrintAllRules() const {
    printf("=== PartitionSort: %zu rules ===\n", rules.size());
    for (size_t i = 0; i < rules.size(); ++i) {
        const Rule &r = rules[i].first;
        printf("Rule[%2zu]: descriptor=0x%" PRIxPTR
               ", priority=%d, id=%d, tag=%d, markedDelete=%d\n",
               i,
               (uintptr_t)r.descriptor,
               r.priority,
               r.id,
               r.tag,
               (int)r.markedDelete);

        // print ranges
        printf("   ranges: ");

        for (int d = 0; d < r.dim; ++d) {
            if (d == 13) {
                bool uplink = (r.range[d][0] == 1);
                printf("[%s] ", uplink ? "UL" : "DL");
            } else {
                printf("[%u–%u] ", r.range[d][0], r.range[d][1]);
            }
        }
        
        // print prefix lengths
        printf("\n   prefixes:");
        for (int d = 0; d < r.dim; ++d) {
            printf(" %u", r.prefix_length[d]);
        }
        printf("\n");
    }
    printf("=== end of rules ===\n");
}
