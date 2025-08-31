#ifndef  PSORT_H
#define  PSORT_H


#include <cstdint>
#include <vector>
#include <array>
#include <unordered_map>
#include <algorithm>   

#include "../cls_no_virtual.h"
#include "OptimizedMITree.h"
#include "SortableRulesetPartitioner.h"
#include "../ElementaryClasses.h"


#define DEBUG_ASSERT 0

using Memory = std::uint32_t;

class PartitionSort final {

public:

	// PartitionSort() {
    //     // Optimization scope: if we know the max number of PDR rules
    //     descriptorIndexMap.reserve(1000);
    // }
	~PartitionSort() {
		for (auto x : mitrees) {
			delete x;
		}
	}

	void ConstructClassifier(const std::vector<Rule>& rules)  {
		
		this->rules.reserve(rules.size());
		for (const auto& r : rules) {
			InsertRule(r);
		}
	}
	int ClassifyAPacket(const Packet& packet) {
		int result = -1;
		int query = 0;
		for (const auto& t : mitrees) {
		
			if (result > t->MaxPriority()){
				break;
			}
			query++;
			result = std::max(t->ClassifyAPacket(packet), result);
		}
		// QueryUpdate(query);
		return result;
		
	}  


	MatchResult ClassifyAPacketMod(const Packet& packet)
	{
		MatchResult best{-1, 0};          // explicit init: priority = –1, desc = 0
		int query = 0;

		for (const auto& t : mitrees) {
		
			if (best.priority > t->MaxPriority())
				break;

			++query;

			MatchResult m = t->ClassifyAPacketMod(packet);
			if (m.priority > best.priority)     
				best = m;
			/* If need tie-breaking on equal priority, handle it here */
		}
		// QueryUpdate(query);
		return best;
	}

	void DeleteRule(size_t index);

	void InsertRule(const Rule& one_rule);
	
	uintptr_t InsertRuleReturnDescriptor(const Rule& one_rule);
	
	void PrintAllRules() const;
	bool DeleteRuleByDescriptor(uintptr_t descriptor);
	
	Memory MemSizeBytes() const {
		int size_total_bytes = 0;
		for (const auto& t : mitrees) {
			size_total_bytes += t->MemoryConsumption();
		}
		int size_array_pointers = mitrees.size();
		int size_of_pointer = 4;
		return size_total_bytes + size_array_pointers*size_of_pointer;
	}
	int MemoryAccess() const {
		return 0;
	}
	size_t NumTables() const {
		return mitrees.size();
	}
	size_t RulesInTable(size_t index) const { return mitrees[index]->NumRules(); }

protected:
	std::vector<OptimizedMITree *> mitrees;
	std::vector<std::pair<Rule,OptimizedMITree *>> rules;

	std::unordered_map<uintptr_t, size_t> descriptorIndexMap;

	 
	void InsertionSortMITrees() {
		int i, j, numLength = mitrees.size();
		OptimizedMITree * key;
		for (j = 1; j < numLength; j++)
		{
			key = mitrees[j];
			for (i = j - 1; (i >= 0) && (mitrees[i]-> MaxPriority() < key-> MaxPriority()); i--)
			{
				mitrees[i + 1] = mitrees[i];
			}
			mitrees[i + 1] = key;
		}
	}

};

CLS_ENSURE_NO_VIRTUAL(PartitionSort);

#endif
